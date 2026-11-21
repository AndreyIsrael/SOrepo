#!/usr/bin/env python3
import argparse
import copy
import io
import os
import random
import re
import shlex
import sys
from collections import deque
from contextlib import redirect_stdout

from fs_sim import STRATEGY_ALIASES, FileSystem, FSError, parse_opts, parse_size
from io_sim import RAID_LEVELS, get_alg
from mem_sim import (ALG_NAMES, CRITICAL, KB, LIVE_ALGS, NORMAL, TYPE_ALIASES, Memory, MemShell, SwapCorrupted,
                     get_replace, kb, mb, pct)

NEW, READY, RUN, BLOCKED, DONE = "NOVO", "PRONTO", "EXECUTANDO", "BLOQUEADO", "CONCLUÍDO"
SCHED_ALGS = {
    "priority_rr": "Prioridade + Round-Robin",
    "rr": "Round-Robin",
    "priority": "Prioridade (preemptivo, sem quantum)",
    "fcfs": "FCFS (First-Come, First-Served)",
}
SCHED_ALIASES = {
    "priorityrr": "priority_rr", "prio_rr": "priority_rr", "prioridade_rr": "priority_rr",
    "round_robin": "rr", "roundrobin": "rr", "prioridade": "priority", "prio": "priority", "fifo": "fcfs",
}
SYSCALLS = {
    "read_disk": ("leitura de disco", "E/S de Disco"),
    "write_disk": ("escrita em disco", "E/S de Disco"),
    "network": ("recepção de rede", "E/S de Rede"),
    "keyboard": ("leitura de teclado", "E/S de Teclado"),
    "print": ("impressão", "E/S de Impressora"),
    "sleep": ("espera temporizada", "Temporizador"),
}
RANDOM_KINDS = ("read_disk", "write_disk", "network", "keyboard")
SYSCALL_RE = re.compile(
    r"^\s*(?P<kind>[a-z_]+)\s*"
    r"(?:at\s*(?:t\s*=\s*)?(?P<at>\d+)\s*(?:ms)?)?\s*"
    r"(?:\(?\s*(?:duration|duracao|duração|dur)\s*[:=]?\s*(?P<dur>\d+)\s*(?:ms)?\s*\)?)?\s*"
    r"(?:(?:file|arquivo)\s*[:=]\s*(?P<file>\S+))?\s*$", re.I)
SCHED_CMDS = {"schedule", "run_simulation", "sched_config", "demo5"}
CREATE_OPTS = ("--name", "-n", "--size", "-s", "--type", "-t", "--file", "-f", "--burst", "--priority", "--syscall",
               "--arrival", "--threads", "--mutex", "--cs", "--refs")


def parse_ms(text, name="tempo"):
    m = re.fullmatch(r"\s*(\d+)\s*(?:ms)?\s*", str(text), re.I)
    if not m:
        raise FSError(f"{name} inválido: '{text}' (use, por exemplo, 8ms)")
    return int(m.group(1))


def get_sched(name):
    key = name.lower().replace("-", "_").replace("+", "_")
    key = SCHED_ALIASES.get(key, key)
    if key not in SCHED_ALGS:
        raise FSError(f"algoritmo de escalonamento desconhecido: {name} (use {', '.join(SCHED_ALGS)})")
    return key


def prio_label(p):
    return {0: "Sistema", 1: "Alta", 2: "Baixa"}.get(p, f"Baixa, nível {p}")


def parse_syscalls(spec):
    calls, rnd = [], False
    for part in [s for s in re.split(r";", spec or "") if s.strip()]:
        if part.strip().lower() in ("random", "aleatorio", "aleatório"):
            rnd = True
            continue
        m = SYSCALL_RE.match(part)
        if not m:
            raise FSError(f"syscall inválida: '{part.strip()}' (ex.: \"read_disk at 3ms (duration: 4ms)\")")
        kind = m.group("kind").lower()
        if kind not in SYSCALLS:
            raise FSError(f"tipo de syscall desconhecido: {kind} (use {', '.join(SYSCALLS)} ou random)")
        if m.group("at") is None:
            raise FSError(f"informe o instante da syscall: '{kind} at 3ms'")
        calls.append({"kind": kind, "at": int(m.group("at")), "dur": int(m.group("dur") or 3),
                      "file": m.group("file"), "random": False})
    calls.sort(key=lambda c: c["at"])
    return calls, rnd


def box(headers, rows, align=None):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) + 2 for i, h in enumerate(headers)]
    align = align or ["^"] * len(headers)
    sep = "+" + "+".join("-" * w for w in widths) + "+"
    out = [sep, "|" + "|".join(f"{h:^{w}}" for h, w in zip(headers, widths)) + "|", sep]
    for r in rows:
        out.append("|" + "|".join(f"{str(c):{a}{w}}" if a != "<" else f" {str(c):<{w - 1}}"
                                  for c, w, a in zip(r, widths, align)) + "|")
    out.append(sep)
    return out


class PCB:
    def __init__(self, pid, name, priority, kind, owner, burst, arrival, syscalls, random_io, threads,
                 mutex, cs, refs):
        self.pid, self.name, self.priority, self.kind, self.owner = pid, name, priority, kind, owner
        self.burst, self.arrival, self.syscalls, self.random_io = burst, arrival, syscalls, random_io
        self.threads, self.mutex, self.cs, self.refs = threads, mutex, cs, refs
        self.loc = 0
        self.killed = False
        self.tasks = []

    def label(self):
        return f"PID {self.pid}"


class Task:
    def __init__(self, pcb, tid, burst):
        self.pcb, self.tid, self.burst = pcb, tid, burst
        self.reset()

    def reset(self):
        self.left = self.burst
        self.done = 0
        self.state = NEW
        self.qused = 0
        self.first = self.finish = None
        self.wait = self.blocked = 0
        self.unblock = None
        self.why = None
        self.sys_i = 0
        self.rand_left = 1 if self.pcb.random_io else 0
        self.cs_state = 0
        self.cs_done = 0
        self.sys_mark = 0

    @property
    def label(self):
        return self.pcb.label() if self.pcb.threads == 1 else f"PID {self.pcb.pid}/T{self.tid}"

    @property
    def prio(self):
        return self.pcb.priority

    @property
    def syscalls(self):
        return self.pcb.syscalls if self.tid == 1 else []


class CPU:
    def __init__(self, alg="priority_rr", quantum=2, seed=42, prob=0.2, preempt=True):
        self.alg, self.quantum, self.seed, self.prob, self.preempt = alg, quantum, seed, prob, preempt
        self.pcbs = []
        self.reset_state()

    def reset_state(self):
        self.t = 0
        self.running = None
        self.queues = {}
        self.mutex = {}
        self.timeline = []
        self.switches = self.dispatches = self.busy = 0
        self.last = None
        self.seg = None
        self.idle_start = None
        self.rng = random.Random(self.seed)
        self.stats = dict.fromkeys(("quantum", "preempt", "syscalls", "mutex_blocks", "refs", "faults"), 0)

    @property
    def tasks(self):
        return [t for p in self.pcbs for t in p.tasks]

    def add(self, pcb):
        n = pcb.threads
        base, extra = divmod(pcb.burst, n)
        pcb.tasks = [Task(pcb, i + 1, base + (1 if i < extra else 0)) for i in range(n)]
        pcb.arrival = max(pcb.arrival, self.t)
        self.pcbs.append(pcb)
        if pcb.arrival <= self.t:
            for task in pcb.tasks:
                self.enqueue(task)

    def restart(self):
        self.reset_state()
        for pcb in self.pcbs:
            pcb.loc = 0
            pcb.killed = False
            for task in pcb.tasks:
                task.reset()
                if pcb.arrival <= 0:
                    self.enqueue(task)

    @property
    def prioritized(self):
        return self.alg in ("priority_rr", "priority")

    @property
    def uses_quantum(self):
        return self.alg in ("priority_rr", "rr")

    def level(self, task):
        return task.prio if self.prioritized else 0

    def enqueue(self, task):
        task.state = READY
        self.queues.setdefault(self.level(task), deque()).append(task)

    def unqueue(self, task):
        for q in self.queues.values():
            if task in q:
                q.remove(task)

    def requeue_all(self):
        ready = [t for lvl in sorted(self.queues) for t in self.queues[lvl]]
        self.queues = {}
        for t in ready:
            self.enqueue(t)

    def best_level(self):
        levels = [lvl for lvl, q in self.queues.items() if q]
        return min(levels) if levels else None

    def pick(self):
        lvl = self.best_level()
        return None if lvl is None else self.queues[lvl].popleft()

    def finished(self):
        return all(t.state == DONE for t in self.tasks)

    def close_idle(self, t):
        if self.idle_start is not None and t > self.idle_start:
            self.timeline.append(("seg", self.idle_start, t, "CPU OCIOSA", "nenhum processo PRONTO"))
        self.idle_start = None

    def dispatch(self, task, t):
        self.unqueue(task)
        if self.last is not None and self.last is not task:
            self.switches += 1
        self.dispatches += 1
        self.last = task
        task.state = RUN
        task.qused = 0
        self.running = task
        self.seg = (task, t)
        self.close_idle(t)

    def leave(self, task, reason, t):
        if self.seg and self.seg[0] is task:
            start = self.seg[1]
            if t > start:
                self.timeline.append(("seg", start, t, task.label, reason))
            else:
                self.timeline.append(("ev", t, None, task.label, reason))
            self.seg = None
        if self.running is task:
            self.running = None

    def event(self, t, label, text):
        self.timeline.append(("ev", t, None, label, text))

    def release(self, owner, t, out):
        name = owner.pcb.mutex
        m = self.mutex[name]
        owner.cs_state = 2
        if m["waiters"]:
            w = m["waiters"].popleft()
            m["owner"] = w
            w.cs_state = 1
            self.enqueue(w)
            out.append(f"[t={t}ms] {owner.label} libera o Mutex '{name}' -> entregue a {w.label}: "
                       f"BLOQUEADO -> PRONTO (adquire o Mutex)")
            self.event(t, None, f"Mutex '{name}' liberado por {owner.label} -> {w.label} BLOQUEADO -> PRONTO")
        else:
            m["owner"] = None
            out.append(f"[t={t}ms] {owner.label} sai da Região Crítica: Mutex '{name}' [LIVRE]")

    def kill(self, pcb, t):
        out = []
        pcb.killed = True
        for task in pcb.tasks:
            if task.state == DONE:
                continue
            self.unqueue(task)
            if task.why and task.why[0] == "mutex":
                m = self.mutex.get(task.why[1])
                if m and task in m["waiters"]:
                    m["waiters"].remove(task)
            if task.cs_state == 1:
                self.release(task, t, out)
            if self.running is task:
                self.leave(task, "processo encerrado (terminate_process)", t)
            task.state = DONE
            task.finish = t
        return out

    def tick(self, hooks=None, force=None):
        t = self.t
        before, after = [], []
        for task in self.tasks:
            if task.state == NEW and task.pcb.arrival <= t:
                self.enqueue(task)
                before.append(f"[t={t}ms] Chegada de {task.label} ({task.pcb.name}): NOVO -> PRONTO "
                              f"(Fila P{self.level(task)})")
                self.event(t, None, f"Chegada: {task.label} NOVO -> PRONTO")
        for task in self.tasks:
            if task.state == BLOCKED and task.why[0] == "io" and task.unblock <= t:
                kind = task.why[1]["kind"]
                self.enqueue(task)
                before.append(f"[t={t}ms] Evento E/S: {task.label} concluiu {kind} -> BLOQUEADO -> PRONTO")
                self.event(t, None, f"Evento E/S: {task.label} encerra {kind} -> Estado BLOQUEADO -> PRONTO")
        r = self.running
        if force is not None and r is not force:
            if r is not None:
                self.leave(r, "Preempção manual (run_simulation --process)", t)
                self.enqueue(r)
            self.dispatch(force, t)
        elif force is None and r is not None and self.preempt and self.prioritized:
            lvl = self.best_level()
            if lvl is not None and lvl < self.level(r):
                nxt = self.queues[lvl][0]
                self.stats["preempt"] += 1
                before.append(f"[t={t}ms] PREEMPÇÃO: {nxt.label} (prioridade {nxt.prio}) chegou à Fila de Pronto; "
                              f"{r.label} (prioridade {r.prio}) EXECUTANDO -> PRONTO")
                self.leave(r, f"Preemptado por {nxt.label} (maior prioridade) -> Volta p/ Fila P{self.level(r)}", t)
                self.enqueue(r)
        for _ in range(len(self.tasks) + 1):
            if self.running is None:
                nxt = self.pick()
                if nxt is None:
                    break
                self.dispatch(nxt, t)
            r = self.running
            sc = None
            if r.sys_i < len(r.syscalls) and r.done >= r.syscalls[r.sys_i]["at"]:
                sc = r.syscalls[r.sys_i]
                r.sys_i += 1
            elif r.rand_left and r.done > r.sys_mark and r.left > 0 and self.rng.random() < self.prob:
                r.rand_left -= 1
                sc = {"kind": self.rng.choice(RANDOM_KINDS), "at": r.done, "dur": self.rng.randint(1, 4),
                      "file": None, "random": True}
            if sc:
                r.sys_mark = r.done
                self.stats["syscalls"] += 1
                lines, block = hooks.syscall(r, sc, t) if hooks else ([], True)
                desc, dev = SYSCALLS[sc["kind"]]
                when = (f"evento aleatório em t={t}ms" if sc["random"]
                        else f"agendada para t={sc['at']}ms de CPU")
                before.append(f"[SYSCALL DETECTADA]: {r.label} atingiu a instrução de {desc} ({when})!")
                before += lines
                if block:
                    r.state = BLOCKED
                    r.why = ("io", sc)
                    r.unblock = t + sc["dur"]
                    before.append(f"- Mudança de Estado: EXECUTANDO -> BLOQUEADO ({dev}).")
                    before.append(f"- Tempo de Retorno Previsto do Bloqueio: {sc['dur']}ms "
                                  f"(Desbloqueio em t={r.unblock}ms).")
                    before.append("- CPU liberada -> Escalonador seleciona próximo processo da Fila de Pronto.")
                    self.leave(r, f"Dispara Syscall {sc['kind']} -> Estado BLOQUEADO (até t={r.unblock}ms)", t)
                    continue
                before.append("- Syscall retornou erro imediatamente: o processo continua EXECUTANDO.")
                self.event(t, None, f"{r.label}: Syscall {sc['kind']} falhou (erro) -> continua EXECUTANDO")
            if r.pcb.mutex and r.cs_state == 0 and r.done >= r.pcb.cs[0]:
                name = r.pcb.mutex
                m = self.mutex.setdefault(name, {"owner": None, "waiters": deque()})
                before.append(f"[CONCORRÊNCIA DE THREADS EM PID {r.pcb.pid}]")
                before.append(f"[t={t}ms] Thread T{r.tid} (PID {r.pcb.pid}) tenta acessar Região Crítica ('{name}').")
                if m["owner"] is None:
                    m["owner"] = r
                    r.cs_state = 1
                    before.append(f"        Mutex [LIVRE] -> T{r.tid} adquire o Mutex [BLOQUEADO].")
                else:
                    o = m["owner"]
                    who = f"T{o.tid}" if o.pcb is r.pcb else o.label
                    before.append(f"        Mutex [BLOQUEADO por {who}]!")
                    before.append(f"        - Mudança de Estado de T{r.tid}: EXECUTANDO -> BLOQUEADO (Aguardando Mutex).")
                    r.state = BLOCKED
                    r.why = ("mutex", name)
                    m["waiters"].append(r)
                    self.stats["mutex_blocks"] += 1
                    self.leave(r, f"Mutex '{name}' ocupado por {o.label} -> BLOQUEADO", t)
                    continue
            break
        r = self.running
        refs = []
        release_now = False
        if r is not None:
            if r.first is None:
                r.first = t
            if hooks:
                refs = hooks.ref(r, t)
            r.done += 1
            r.left -= 1
            r.qused += 1
            self.busy += 1
            if r.cs_state == 1:
                r.cs_done += 1
                release_now = r.cs_done >= r.pcb.cs[1] or r.left == 0
        elif self.idle_start is None:
            self.idle_start = t
        for task in self.tasks:
            if task.state == READY:
                task.wait += 1
            elif task.state == BLOCKED:
                task.blocked += 1
        self.t = t + 1
        if release_now:
            self.release(r, t + 1, after)
        if r is not None:
            lvl = self.level(r)
            if r.left == 0:
                r.state = DONE
                r.finish = t + 1
                empty = self.prioritized and not self.queues.get(lvl)
                self.leave(r, f"{r.label} CONCLUÍDO!" + (f" (Fila P{lvl} VAZIA)" if empty else ""), t + 1)
                after.append(f"[t={t + 1}ms] {r.label}: EXECUTANDO -> CONCLUÍDO "
                             f"(TAT = {t + 1 - r.pcb.arrival}ms, WT = {r.wait}ms)")
                if hooks and all(x.state == DONE for x in r.pcb.tasks):
                    after += hooks.finish(r.pcb)
            elif self.uses_quantum and r.qused >= self.quantum:
                self.stats["quantum"] += 1
                qname = f"Fila P{lvl}" if self.prioritized else "Fila de Pronto"
                self.leave(r, f"Quantum {self.quantum}ms expirou -> Volta p/ {qname}", t + 1)
                self.enqueue(r)
                after.append(f"[t={t + 1}ms] Quantum de {self.quantum}ms de {r.label} expirou: "
                             f"EXECUTANDO -> PRONTO (fim da {qname})")
        return {"t": t, "task": r, "before": before, "refs": refs, "after": after}

    def run_all(self, hooks=None, limit=100000, each=None):
        start = self.t
        while not self.finished() and self.t - start < limit:
            rec = self.tick(hooks)
            if each:
                each(rec)
        self.close_idle(self.t)

    def metrics(self, tasks=None):
        tasks = tasks if tasks is not None else self.tasks
        rows, done = [], [t for t in tasks if t.state == DONE and not t.pcb.killed]
        for t in tasks:
            tat = t.finish - t.pcb.arrival if t.state == DONE and not t.pcb.killed else None
            resp = t.first - t.pcb.arrival if t.first is not None else None
            rows.append((t, tat, resp))
        n = len(done)
        agg = {
            "awt": sum(t.wait for t in done) / n if n else 0,
            "att": sum(t.finish - t.pcb.arrival for t in done) / n if n else 0,
            "art": sum(t.first - t.pcb.arrival for t in done) / n if n else 0,
            "n": n,
        }
        if tasks:
            begin = min(t.pcb.arrival for t in tasks)
            end = max((t.finish for t in tasks if t.finish is not None), default=self.t)
            agg["span"] = max(0, end - begin)
            agg["busy"] = sum(t.done for t in tasks)
        else:
            agg["span"] = agg["busy"] = 0
        return rows, agg


HELP5 = """
ETAPA 5 - PROCESSOS, THREADS E ESCALONAMENTO
  Criação com perfil de E/S
    create_process --name N --burst 8ms --priority 1 [--type normal|critical] [--arrival 0ms]
                   [--syscall "read_disk at 3ms (duration: 4ms)"] [--syscall random]
                   [--threads 2 --mutex Buffer_Video --cs 1:2] [--size 32KB] [--refs "0 1 W2"]
        syscalls: read_disk, write_disk, network, keyboard, print, sleep (várias separadas por ';')
        'at' é o tempo de CPU do processo (thread T1) em que a instrução da syscall é atingida
        read_disk/write_disk aceitam 'file=/caminho' (E/S real no disco, com permissões do dono)
        --cs início:duração = após quantos ms de CPU a thread pede o mutex e por quantos ms o mantém
  Execução e escalonamento (MODO_KERNEL)
    run_simulation [--process N] --steps 3      executa passo a passo (referências a páginas + RAM)
    schedule [--algorithm Priority_RR|RR|Priority|FCFS] [--quantum 2ms] [--reset] [--trace]
                                                executa até concluir: linha do tempo + métricas
    sched_config [--algorithm A] [--quantum Q] [--seed S] [--random-prob 0.2] [--preempt on|off]
  Consulta
    queues                                      filas por prioridade, estados, mutexes
    metrics                                     WT, TAT, resposta, trocas de contexto, CPU, vazão
    compare_sched [--quantum 2ms] [--algs fcfs,rr,priority,priority_rr]   compara algoritmos
    demo5                                       demonstração da etapa 5 (exemplos 5.1 a 5.4)
"""

DEMOS5 = [
    "# Preparação: disco, RAM pequena (12 molduras) para forçar substituições e escalonador",
    "io_log off",
    "format --strategy indexada --block-size 4KB --blocks 128",
    "mem_config --frames 12 --swap-slots 64 --force",
    "replace_alg lru",
    "sched_config --algorithm Priority_RR --quantum 2ms --seed 24 --random-prob 0.25 --preempt on",
    "# Exemplo 5.1 - criação de processos com perfil de E/S (syscalls agendadas e aleatórias)",
    "create_process --name \"App_Web\" --burst 8ms --priority 1 --syscall \"read_disk at 3ms (duration: 4ms)\"",
    "create_process --name \"App_Render\" --burst 5ms --priority 2 --syscall \"random\" --threads 2 --mutex Buffer_Video --cs 1:2",
    "create_process --name \"App_Log\" --burst 4ms --priority 1 --syscall \"write_disk at 2ms (duration: 1ms)\"",
    "create_process --name \"Kernel_Watchdog\" --type critical --size 128KB --burst 2ms --priority 0 --arrival 9ms",
    "queues",
    "# Exemplo 5.2 - execução com referências a páginas e atualização da RAM (LRU)",
    "run_simulation --process App_Web --steps 3",
    "# Exemplo 5.3 - bloqueio por syscall embutida e mutex concorrente",
    "run_simulation --steps 1",
    "run_simulation --process App_Render --steps 4",
    "queues",
    "# Exemplo 5.4 - escalonamento combinado (Prioridade + Round-Robin) e métricas finais",
    "schedule --algorithm Priority_RR --quantum 2ms --reset",
    "compare_sched --quantum 2ms",
    "compare_sched --quantum 4ms",
    "# Integração com as etapas 3 e 4: dono do processo, permissões nas syscalls e memória",
    "groupadd devs",
    "useradd carlos --group devs --password Carlos@123",
    "login --user carlos --password Carlos@123",
    "create_process --name \"Carlos_Bisbilhoteiro\" --burst 3ms --priority 2 --syscall \"read_disk at 1ms (duration: 2ms) file=/sistema/config.sys\"",
    "create_process --name \"Carlos_Relatorio\" --burst 3ms --priority 2 --syscall \"write_disk at 1ms (duration: 1ms)\"",
    "create_process --name \"Carlos_Driver\" --type critical --burst 2ms --priority 0",
    "schedule",
    "su root --password root",
    "schedule",
    "cat /tmp/Carlos_Relatorio.out",
    "memory_status",
    "logs --tail 6",
]


class ProcShell(MemShell):
    def __init__(self, fs, color=True, root_password="root", cpu=None, **kw):
        self.cpu = cpu or CPU()
        self.cpu_base = 0
        self.mrng = random.Random(self.cpu.seed)
        self.touched = {}
        self.evicted = None
        self.forced_last = None
        super().__init__(fs, color, root_password, **kw)
        cmds = {
            "run_simulation": self.cmd_run_simulation, "schedule": self.cmd_schedule,
            "sched_config": self.cmd_sched_config, "queues": self.cmd_queues, "metrics": self.cmd_metrics,
            "compare_sched": self.cmd_compare_sched, "demo5": self.cmd_demo5,
        }
        self.commands.update({k: self.guard(k, h) for k, h in cmds.items()})
        self.commands["create_process"] = self.guard("create_process", self.counted("create_process",
                                                                                     self.cmd_create_process))
        self.commands["terminate_process"] = self.guard("terminate_process",
                                                        self.counted("terminate_process", self.cmd_terminate_process))
        self.commands["kill"] = self.commands["terminate_process"]

    def needs_kernel(self, name, args):
        if name in SCHED_CMDS:
            return True
        if name == "create_process":
            _, opts = parse_opts(args, valued=CREATE_OPTS)
            return TYPE_ALIASES.get(opts.get("--type", opts.get("-t", "normal")).lower()) == CRITICAL
        return super().needs_kernel(name, args)

    def banner(self):
        print(self.s("Simulador de SO - Etapa 5: Processos, Threads e Escalonamento (integra as etapas 1 a 4)", "1"))
        super().banner()
        c = self.cpu
        print(f"CPU: {SCHED_ALGS[c.alg]} | quantum {c.quantum}ms | semente {c.seed}. "
              "Digite 'demo5' para a demonstração da etapa 5.\n")

    def cmd_help(self, args):
        super().cmd_help(args)
        print(HELP5)

    def find_pcb(self, key):
        for p in self.cpu.pcbs:
            if p.name == key or str(p.pid) == str(key):
                return p
        return None

    def cmd_create_process(self, args):
        if not any(a == "--burst" or a.startswith("--burst=") for a in args):
            return super().cmd_create_process(args)
        pos, opts = parse_opts(args, valued=CREATE_OPTS)
        name = opts.get("--name", opts.get("-n")) or (pos[0] if pos else None)
        if not name:
            raise FSError("uso: create_process --name N --burst 8ms --priority 1 [--syscall ...]")
        kind = TYPE_ALIASES.get(opts.get("--type", opts.get("-t", "normal")).lower())
        if kind is None:
            raise FSError("tipo inválido (use critical ou normal)")
        burst = parse_ms(opts["--burst"], "burst")
        if burst < 1:
            raise FSError("o burst deve ser >= 1ms")
        try:
            prio = int(opts.get("--priority", "0" if kind == CRITICAL else "1"))
            threads = int(opts.get("--threads", "1"))
        except ValueError:
            raise FSError("--priority e --threads devem ser inteiros")
        if prio < 0 or prio > 9:
            raise FSError("prioridade deve estar entre 0 (sistema) e 9")
        if kind == NORMAL and prio == 0:
            raise FSError("a prioridade 0 é reservada a processos críticos")
        if not 1 <= threads <= 8 or threads > burst:
            raise FSError("--threads deve estar entre 1 e 8 (e não exceder o burst)")
        arrival = parse_ms(opts.get("--arrival", "0"), "chegada")
        syscalls, rnd = parse_syscalls(opts.get("--syscall"))
        first_burst = -(-burst // threads)
        for sc in syscalls:
            if sc["at"] >= first_burst:
                raise FSError(f"syscall em t={sc['at']}ms fora do burst de CPU da thread principal "
                              f"(0..{first_burst - 1}ms)")
            if sc["dur"] < 1:
                raise FSError("a duração da syscall deve ser >= 1ms")
        mutex = opts.get("--mutex")
        cs = (1, 2)
        if "--cs" in opts:
            m = re.fullmatch(r"\s*(\d+)\s*(?:ms)?\s*:\s*(\d+)\s*(?:ms)?\s*", opts["--cs"])
            if not m or int(m.group(2)) < 1:
                raise FSError("--cs deve ser início:duração (ex.: 1:2)")
            cs = (int(m.group(1)), int(m.group(2)))
        refs = None
        if "--refs" in opts:
            refs = []
            for tok in re.split(r"[\s,]+", opts["--refs"].strip()):
                m = re.fullmatch(r"([rRwW]?)(\d+)", tok)
                if not m:
                    raise FSError(f"referência inválida: '{tok}'")
                refs.append((m.group(1).upper() == "W", int(m.group(2))))
        if self.mem.find(name) or self.find_pcb(name):
            raise FSError(f"já existe um processo chamado '{name}'")
        size = parse_size(opts.get("--size", opts.get("-s", "256KB" if kind == CRITICAL else "32KB")))
        blob = None
        src = opts.get("--file", opts.get("-f"))
        if src:
            if kind == CRITICAL:
                raise FSError("processos críticos são carregados com --size")
            node = self.fs.read(src)
            self.require(node, "rx")
            blob = self.read_through(node, verbose=False)
            if "--size" not in opts and "-s" not in opts:
                size = node.size
        buf = io.StringIO()
        old = self.storage.verbose
        self.storage.verbose = False
        try:
            with redirect_stdout(buf):
                if kind == CRITICAL:
                    self.create_critical(name, size)
                else:
                    self.create_normal(name, size, blob, src)
        finally:
            self.storage.verbose = old
        mp = self.mem.find(name)
        if mp is None:
            print(buf.getvalue().rstrip())
            return
        if refs:
            bad = [n for _, n in refs if n >= max(1, len(mp.pages))] if not mp.critical else []
            if bad:
                self.release(mp)
                raise FSError(f"--refs cita página {bad[0]}, mas o processo tem {len(mp.pages)} página(s)")
        pcb = PCB(mp.pid, name, prio, kind, self.euser, burst, arrival, syscalls, rnd, threads, mutex, cs, refs)
        self.cpu.add(pcb)
        print(self.s(f"[CRIAÇÃO DE PROCESSO] PID: {pcb.pid} | Nome: {name} | Prioridade: {prio} ({prio_label(prio)})",
                     "1"))
        if kind == CRITICAL:
            print(f"Alocação     : Área Reservada contígua [{mb(mp.base)} MB até {mb(mp.base + mp.size)} MB] "
                  f"({kb(mp.size)}, sem paginação)")
        else:
            print(f"Alocação     : Memória Virtual Paginada (Tabela de Páginas criada: {len(mp.pages)} páginas, "
                  f"imagem no swap)")
        print(f"CPU Burst    : {burst}ms | Chegada: t={pcb.arrival}ms | Tipo: {kind} | Dono: {pcb.owner}")
        if syscalls:
            for sc in syscalls:
                extra = f" | arquivo {sc['file']}" if sc["file"] else ""
                print(f"Syscall/I/O  : {sc['kind']} agendada para t={sc['at']}ms (Duração do Bloqueio: "
                      f"{sc['dur']}ms){extra}")
        if rnd:
            print(f"Syscall/I/O  : Evento Aleatório Habilitado (probabilidade {self.cpu.prob:g} por ms de CPU, "
                  "1 evento por thread)")
        if not syscalls and not rnd:
            print("Syscall/I/O  : nenhuma (processo CPU-bound)")
        if threads > 1:
            parts = ", ".join(f"T{t.tid}: {t.burst}ms" for t in pcb.tasks)
            print(f"Threads      : {threads} ({parts})")
        if mutex:
            print(f"Mutex        : '{mutex}' (pedido após {cs[0]}ms de CPU de cada thread, mantido por {cs[1]}ms)")
        if pcb.arrival <= self.cpu.t:
            print(f"Ciclo de vida: NOVO -> PRONTO (admitido em t={self.cpu.t}ms, Fila P{self.cpu.level(pcb.tasks[0])})")
            print("Estado Inicial: " + self.s("PRONTO", "32;1"))
        else:
            print(f"Ciclo de vida: NOVO (admissão na Fila de Pronto em t={pcb.arrival}ms)")
            print("Estado Inicial: " + self.s("NOVO", "33;1"))
        self.log("PROC_CRIAR", f"PID {pcb.pid} '{name}' burst={burst}ms prio={prio}")

    def cmd_terminate_process(self, args):
        pos, opts = parse_opts(args, valued=("--name", "-n", "--pid", "--process", "-p"))
        key = opts.get("--name") or opts.get("-n") or opts.get("--pid") or opts.get("--process") or opts.get("-p") \
            or (pos[0] if pos else None)
        pcb = self.find_pcb(key)
        super().cmd_terminate_process(args)
        if pcb is not None and self.mem.find(pcb.pid) is None and not pcb.killed:
            for line in self.cpu.kill(pcb, self.cpu.t):
                print(line)
            print(f"Escalonador: {pcb.label()} removido das filas (estado CONCLUÍDO por encerramento).")

    def ensure_memory(self, pcb):
        mem = self.mem
        mp = mem.procs.get(pcb.pid)
        if mp is not None and mp.name == pcb.name:
            return
        saved = (mem.next_pid, mem.next_crit)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                if pcb.kind == CRITICAL:
                    mem.next_crit = pcb.pid
                    self.create_critical(pcb.name, 256 * KB)
                else:
                    mem.next_pid = pcb.pid
                    self.create_normal(pcb.name, 32 * KB, None, None)
        except FSError:
            pass
        finally:
            mem.next_pid = max(saved[0], mem.next_pid if pcb.kind != CRITICAL else saved[0])
            mem.next_crit = max(saved[1], mem.next_crit if pcb.kind == CRITICAL else saved[1])

    def evict(self, f, say):
        p, pg = self.mem.frames[f]
        self.evicted = (p, pg, self.mem.clock - (pg.last or 0), pg.dirty)
        super().evict(f, say)

    def next_page(self, pcb, task, npages):
        if pcb.refs:
            return pcb.refs[task.done % len(pcb.refs)]
        r = self.mrng
        if r.random() < 0.3:
            pcb.loc = r.randrange(npages)
        return r.random() < 0.25, (pcb.loc + r.choice((0, 0, 1, 2))) % npages

    def ref(self, task, t):
        pcb, mem = task.pcb, self.mem
        mp = mem.procs.get(pcb.pid)
        if mp is None or mp.name != pcb.name:
            return ["CPU executa instrução (processo sem memória associada)"]
        if mp.critical:
            off = self.mrng.randrange(0, mp.size, 4)
            return [f"CPU acessa: deslocamento 0x{off:05X} -> endereço físico 0x{mp.base + off:08X} "
                    "[Área Reservada - Base/Limite, sem paginação]"]
        write, page = self.next_page(pcb, task, len(mp.pages))
        self.cpu.stats["refs"] += 1
        self.cpu_base = max(self.cpu_base, mem.clock - t - 1)
        mem.clock = self.cpu_base + t + 1
        old = (mem.tick, mem.fault_cost)
        mem.tick = mem.fault_cost = 0
        self.evicted = None
        try:
            info = self.access(mp, page, 0, write, f"{task.label}@t{t}" if write else None, verbose=False)
        except SwapCorrupted as e:
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.corrupted(e.proc, e.page)
            self.cpu.kill(pcb, t + 1)
            return [f"CPU acessa: Página Lógica {page:02d} -> [PAGE FAULT!]"] + buf.getvalue().rstrip().splitlines()
        finally:
            mem.tick, mem.fault_cost = old
        f = info["frame"]
        alg = ALG_NAMES[self.alg]
        op = "escrita" if write else "leitura"
        if info["hit"]:
            self.touched[f] = (pcb.pid, page, "HIT", t + 1)
            hist = {"lru": f"Histórico LRU: Pág {page:02d} atualizada (t={t + 1}ms)",
                    "fifo": "Fila FIFO inalterada (acerto)",
                    "segunda_chance": f"bit R da Pág {page:02d} := 1"}[self.alg]
            return [f"CPU acessa ({op}): Página Lógica {page:02d} -> [RAM: Moldura {f:02d} - HIT] | {hist}"]
        self.cpu.stats["faults"] += 1
        self.touched[f] = (pcb.pid, page, "PAGE FAULT (NEW)", t + 1)
        lines = [f"CPU acessa ({op}): Página Lógica {page:02d} -> " + self.s("[PAGE FAULT!]", "31;1")]
        if self.evicted:
            p, pg, age, dirty = self.evicted
            self.touched = {k: v for k, v in self.touched.items() if not (v[0] == p.pid and v[1] == pg.num)}
            lines.append(f"Substituição {alg}: Página Lógica {pg.num:02d} do PID {p.pid} (não usada há {age}ms) "
                         + ("removida para o Swap (página modificada gravada no disco)." if dirty
                            else "removida (cópia no Swap já atualizada, sem escrita)."))
        else:
            lines.append("Moldura livre disponível: sem substituição.")
        lines.append(f"Página Lógica {page:02d} alocada na Moldura {f:02d} (lida do Swap, slot {mp.pages[page].slot}).")
        return lines

    def syscall(self, task, sc, t):
        pcb = task.pcb
        kind = sc["kind"]
        if kind not in ("read_disk", "write_disk"):
            return [f"- Dispositivo: {SYSCALLS[kind][1]} (sem acesso ao sistema de arquivos)."], True
        st = self.storage
        try:
            if kind == "read_disk":
                path = sc["file"] or "/sistema/logs/app.log"
                node = self.fs.read(path)
                if not self.allowed(node, "r", pcb.owner):
                    self.log("SYSCALL_NEGADA", f"PID {pcb.pid} read_disk {path} (dono {pcb.owner})", "ALERTA")
                    return [self.s(f"- [EACCES]: '{pcb.owner}' (dono do PID {pcb.pid}) não tem permissão de leitura "
                                   f"em '{path}' ({self.mode_str(node)}). Tentativa registrada nos logs.", "31;1")], False
                if getattr(node, "cipher", None) is not None:
                    return [f"- [EIO]: '{path}' está criptografado (etapa 3)."], False
                st.read(node, verbose=False)
                lbas = [st.meta_lba(node)] + list(node.blocks)
                return [f"- E/S real: leitura de '{path}' ({node.size} B) -> {len(lbas)} bloco(s) lógicos "
                        f"(LBA {', '.join(st.bnum(b) for b in lbas)}) via {st.array.title}."], True
            path = sc["file"] or f"/tmp/{pcb.name}.out"
            line = f"[t={t}ms] {task.label} ({pcb.name}) write_disk\n"
            try:
                node = self.fs.read(path)
            except FSError:
                node = None
            if node is None:
                parent, _ = self.fs.resolve_parent(path)
                if not (self.allowed(parent, "w", pcb.owner) and self.allowed(parent, "x", pcb.owner)):
                    return [self.s(f"- [EACCES]: '{pcb.owner}' não pode criar arquivos em '{parent.path}'.", "31;1")], False
                node = self.fs.create(path, 0, line)
                self.sys_set(node, pcb.owner, self.primary(pcb.owner), 0o644)
            else:
                if not self.allowed(node, "w", pcb.owner):
                    self.log("SYSCALL_NEGADA", f"PID {pcb.pid} write_disk {path}", "ALERTA")
                    return [self.s(f"- [EACCES]: '{pcb.owner}' não tem permissão de escrita em '{path}'.", "31;1")], False
                if getattr(node, "cipher", None) is not None or getattr(node, "swap_area", None) is not None:
                    return [f"- [EPERM]: '{path}' não pode ser alterado por write_disk."], False
                self.fs.write(path, line, append=True)
            st.sync(f"syscall write_disk PID {pcb.pid}", [node])
            return [f"- E/S real: escrita em '{path}' ({node.size} B) -> bloco(s) "
                    f"{', '.join(st.bnum(b) for b in node.blocks[-1:])} via {st.array.title}."], True
        except FSError as e:
            return [f"- [ERRO DE E/S]: {e}"], False

    def finish(self, pcb):
        mp = self.mem.procs.get(pcb.pid)
        if mp is None or mp.name != pcb.name:
            return []
        if mp.critical:
            del self.mem.procs[mp.pid]
            return [f"- {pcb.label()} CONCLUÍDO: {mp.size // KB} KB liberados na Área Reservada."]
        frames, slots = self.release(mp)
        return [f"- {pcb.label()} CONCLUÍDO: {len(frames)} moldura(s) e {len(slots)} slot(s) de swap liberados."]

    def quiet(self):
        shell = self

        class Quiet:
            def __enter__(self):
                self.old = shell.storage.verbose
                shell.storage.verbose = False
                shell.cpu_base = max(shell.cpu_base, shell.mem.clock - shell.cpu.t)

            def __exit__(self, *exc):
                shell.storage.verbose = self.old
        return Quiet()

    def print_rec(self, rec, k=None):
        for line in rec["before"]:
            print(self.colorize(line))
        r = rec["task"]
        head = f"STEP {k} " if k is not None else ""
        if r is not None:
            print(self.s(f"--- {head}(t={rec['t'] + 1}ms) | Executando {r.label} ({r.pcb.name}) ---", "1"))
        else:
            print(self.s(f"--- {head}(t={rec['t'] + 1}ms) | CPU OCIOSA ---", "2"))
        for line in rec["refs"] + rec["after"]:
            print(self.colorize(line))

    def colorize(self, line):
        if line.startswith("[SYSCALL") or line.startswith("[CONCORR"):
            return self.s(line, "33;1")
        if "PREEMPÇÃO" in line:
            return self.s(line, "35")
        return line

    def forced_task(self, pcb):
        cpu = self.cpu
        r = cpu.running
        if r is not None and r.pcb is pcb and (not cpu.uses_quantum or r.qused < cpu.quantum):
            return r
        ready = [t for t in pcb.tasks if t.state in (READY, RUN)]
        if not ready:
            return None
        if self.forced_last in pcb.tasks:
            i = pcb.tasks.index(self.forced_last)
            order = pcb.tasks[i + 1:] + pcb.tasks[:i + 1]
            ready = [t for t in order if t in ready]
        self.forced_last = ready[0]
        return ready[0]

    def cmd_run_simulation(self, args):
        _, opts = parse_opts(args, valued=("--process", "-p", "--steps", "-n"))
        try:
            steps = int(opts.get("--steps", opts.get("-n", "1")))
        except ValueError:
            raise FSError("--steps deve ser inteiro")
        if steps < 1:
            raise FSError("--steps deve ser >= 1")
        pcb = None
        if "--process" in opts or "-p" in opts:
            pcb = self.find_pcb(opts.get("--process", opts.get("-p")))
            if pcb is None:
                raise FSError("processo não está no escalonador (crie-o com --burst)")
        cpu = self.cpu
        self.touched = {}
        warned = False
        with self.quiet():
            for k in range(1, steps + 1):
                if cpu.finished():
                    print("Todos os processos estão CONCLUÍDOS.")
                    break
                force = self.forced_task(pcb) if pcb else None
                if pcb and force is None and not warned:
                    state = ", ".join(f"{t.label}: {t.state}" for t in pcb.tasks)
                    print(self.s(f"[{pcb.label()} não está PRONTO ({state}) -> o escalonador escolhe o próximo]", "2"))
                    warned = True
                print()
                self.print_rec(cpu.tick(self, force), k)
        if self.touched:
            print()
            print(self.s("[RESUMO DA GERÊNCIA DE MEMÓRIA (RAM DINÂMICA)]", "1"))
            rows = [(f"Moldura {f:02d}", f"PID {pid} / P{pg}", state, f"t = {t} ms")
                    for f, (pid, pg, state, t) in sorted(self.touched.items(), key=lambda x: x[1][3])]
            for line in box(["Moldura RAM (F)", "Processo/Pág", "Estado de Acesso", "Último Acesso (LRU)"],
                            rows, ["^", "^", "<", "<"]):
                print(line)
            used = sum(1 for x in self.mem.frames if x)
            print(f"Molduras ocupadas: {used}/{self.mem.nframes} | algoritmo de substituição: {ALG_NAMES[self.alg]}")

    def ready_listing(self):
        cpu = self.cpu
        pending = [t for t in cpu.tasks if t.state != DONE]
        levels = sorted({cpu.level(t) for t in pending})
        for lvl in levels:
            items = [t for t in pending if cpu.level(t) == lvl]
            text = ", ".join(f"{t.label} (Burst {t.left}ms" + (f", chega em t={t.pcb.arrival}ms" if t.state == NEW else "")
                             + (f", {t.state}" if t.state == BLOCKED else "") + ")" for t in items)
            name = f"Prioridade {lvl} ({prio_label(lvl)})" if cpu.prioritized else "Fila única"
            print(f"- {name:<22}: [{text}]")

    def timeline_lines(self, entries):
        keyed = sorted(enumerate(entries), key=lambda x: (x[1][1], 1 if x[1][0] == "seg" else 0, x[0]))
        out = []
        for _, e in keyed:
            if e[0] == "seg":
                span = f"[{e[1]:>2}ms - {e[2]:>2}ms]"
                if e[3] == "CPU OCIOSA":
                    out.append(self.s(f"{span} CPU OCIOSA ({e[4]})", "2"))
                else:
                    out.append(f"{span} Executando {e[3]:<9} | {e[4]}")
            else:
                text = e[4] if e[3] is None else f"{e[3]}: {e[4]}"
                out.append(self.s(f"[{e[1]:>2}ms]{' ' * 10}{text}", "2"))
        return out

    def cmd_schedule(self, args):
        _, opts = parse_opts(args, valued=("--algorithm", "-a", "--quantum", "-q", "--until"),
                             flags=("--reset", "--trace"))
        cpu = self.cpu
        if not cpu.pcbs:
            raise FSError("nenhum processo no escalonador: use create_process ... --burst Nms")
        self.apply_config(opts)
        if "--reset" in opts:
            cpu.restart()
            self.mrng = random.Random(cpu.seed)
            for pcb in cpu.pcbs:
                self.ensure_memory(pcb)
            print(self.s("[REINÍCIO] Carga de trabalho restaurada para t=0ms (bursts, syscalls e mutexes).", "2"))
        if cpu.finished():
            print("Todos os processos já estão CONCLUÍDOS (use --reset para reexecutar a carga).")
            return
        print(self.s(f"[ESCALONADOR] {SCHED_ALGS[cpu.alg]}" + (f" | Quantum {cpu.quantum}ms" if cpu.uses_quantum else "")
                     + f" | início em t={cpu.t}ms", "1"))
        print("Fila de Pronto Inicial:")
        self.ready_listing()
        mark = len(cpu.timeline)
        limit = parse_ms(opts["--until"], "--until") - cpu.t if "--until" in opts else 100000
        trace = "--trace" in opts
        with self.quiet():
            cpu.run_all(self, max(1, limit), (lambda rec: (print(), self.print_rec(rec))) if trace else None)
        print()
        print(self.s("--- LINHA DO TEMPO DA CPU ---", "1"))
        entries = cpu.timeline[mark:]
        if cpu.seg and cpu.t > cpu.seg[1]:
            entries = entries + [("seg", cpu.seg[1], cpu.t, cpu.seg[0].label,
                                  f"em execução (simulação pausada em t={cpu.t}ms)")]
        for line in self.timeline_lines(entries):
            print(line)
        print()
        self.report()

    def report(self, rows=None, agg=None, cpu=None):
        cpu = cpu or self.cpu
        if rows is None:
            rows, agg = cpu.metrics()
        print(self.s(f"{' MÉTRICAS FINAIS DO ESCALONADOR ':=^84}", "1"))
        table = []
        for t, tat, resp in rows:
            table.append((t.label, t.prio, f"{t.pcb.arrival} ms", f"{t.burst} ms", f"{t.wait} ms",
                          "-" if tat is None else f"{tat} ms", "-" if resp is None else f"{resp} ms",
                          f"{t.blocked} ms", "encerrado" if t.pcb.killed else t.state))
        for line in box(["Processo", "Prioridade", "Chegada", "Burst", "Espera (WT)", "Turnaround (TAT)",
                         "Resposta", "Bloqueado", "Estado"], table):
            print(line)
        busy, span = agg["busy"], agg["span"]
        print()
        print(f"* Tempo Médio de Espera (AWT)   : {agg['awt']:.2f} ms")
        print(f"* Tempo Médio de Retorno (ATT)  : {agg['att']:.2f} ms")
        print(f"* Tempo Médio de Resposta (ART) : {agg['art']:.2f} ms")
        print(f"* Trocas de Contexto Totais     : {cpu.switches} trocas ({cpu.dispatches} despachos)")
        print(f"* Utilização Global da CPU      : {pct(busy, span) if span else '0.0%'} ({busy} ms ocupada em {span} ms)")
        print(f"* Vazão (throughput)            : {agg['n']} processo(s)/thread(s) em {span} ms "
              f"= {agg['n'] * 1000 / span if span else 0:.1f} por segundo")
        st = cpu.stats
        print(f"* Quantum expirado / Preempções : {st['quantum']} / {st['preempt']}")
        print(f"* Syscalls / Bloqueios por Mutex: {st['syscalls']} / {st['mutex_blocks']}")
        if st["refs"]:
            print(f"* Referências à memória virtual : {st['refs']} | page faults: {st['faults']} "
                  f"({pct(st['faults'], st['refs'])}) | algoritmo {ALG_NAMES[self.alg]}")
        print("=" * 84)

    def cmd_metrics(self, args):
        if not self.cpu.pcbs:
            raise FSError("nenhum processo no escalonador")
        print(self.s(f"[MÉTRICAS ATÉ t={self.cpu.t}ms] (processos não concluídos aparecem com TAT '-')", "2"))
        self.report()

    def cmd_queues(self, args):
        cpu = self.cpu
        print(self.s(f"[ESTADO DO ESCALONADOR] t = {cpu.t}ms | {SCHED_ALGS[cpu.alg]}"
                     + (f" | quantum {cpu.quantum}ms" if cpu.uses_quantum else ""), "1"))
        if not cpu.pcbs:
            print("Nenhum processo criado com --burst.")
            return
        r = cpu.running
        print(f"EXECUTANDO : {r.label} ({r.pcb.name}, restam {r.left}ms, quantum {r.qused}/{cpu.quantum})" if r
              else "EXECUTANDO : - (CPU livre)")
        for lvl in sorted(cpu.queues):
            q = cpu.queues[lvl]
            if not q:
                continue
            name = f"Fila P{lvl} ({prio_label(lvl)})" if cpu.prioritized else "Fila única"
            print(f"{name:<18}: [" + ", ".join(f"{t.label} (resta {t.left}ms)" for t in q) + "]")
        blocked = [t for t in cpu.tasks if t.state == BLOCKED]
        if blocked:
            print("BLOQUEADO  : " + ", ".join(
                f"{t.label} ({t.why[1]['kind']} até t={t.unblock}ms)" if t.why[0] == "io"
                else f"{t.label} (Mutex '{t.why[1]}')" for t in blocked))
        new = [t for t in cpu.tasks if t.state == NEW]
        if new:
            print("NOVO       : " + ", ".join(f"{t.label} (chegada t={t.pcb.arrival}ms)" for t in new))
        done = [t for t in cpu.tasks if t.state == DONE]
        if done:
            print("CONCLUÍDO  : " + ", ".join(t.label for t in done))
        for name, m in cpu.mutex.items():
            o = m["owner"]
            print(f"Mutex '{name}': " + (f"[BLOQUEADO por {o.label}]" if o else "[LIVRE]")
                  + (" | espera: [" + ", ".join(w.label for w in m["waiters"]) + "]" if m["waiters"] else ""))
        rows = [(t.label, t.pcb.name, t.state, t.prio, f"{t.done}/{t.burst} ms", f"{t.wait} ms", t.pcb.owner)
                for t in cpu.tasks]
        for line in box(["Unidade", "Nome", "Estado", "Prio", "CPU usada", "Espera", "Dono"], rows):
            print(line)

    def apply_config(self, opts):
        cpu = self.cpu
        if "--algorithm" in opts or "-a" in opts:
            cpu.alg = get_sched(opts.get("--algorithm", opts.get("-a")))
            cpu.requeue_all()
        if "--quantum" in opts or "-q" in opts:
            q = parse_ms(opts.get("--quantum", opts.get("-q")), "quantum")
            if q < 1:
                raise FSError("o quantum deve ser >= 1ms")
            cpu.quantum = q

    def cmd_sched_config(self, args):
        _, opts = parse_opts(args, valued=("--algorithm", "-a", "--quantum", "-q", "--seed", "--random-prob",
                                           "--preempt"))
        cpu = self.cpu
        self.apply_config(opts)
        if "--seed" in opts:
            try:
                cpu.seed = int(opts["--seed"])
            except ValueError:
                raise FSError("--seed deve ser inteiro")
            cpu.rng = random.Random(cpu.seed)
            self.mrng = random.Random(cpu.seed)
        if "--random-prob" in opts:
            try:
                p = float(opts["--random-prob"])
            except ValueError:
                raise FSError("--random-prob deve ser um número entre 0 e 1")
            if not 0 <= p <= 1:
                raise FSError("--random-prob deve estar entre 0 e 1")
            cpu.prob = p
        if "--preempt" in opts:
            if opts["--preempt"] not in ("on", "off"):
                raise FSError("--preempt on|off")
            cpu.preempt = opts["--preempt"] == "on"
        print(self.s("[CONFIGURAÇÃO DO ESCALONADOR]", "1"))
        print(f"Algoritmo  : {SCHED_ALGS[cpu.alg]}" + (f" | Quantum {cpu.quantum}ms" if cpu.uses_quantum else ""))
        print(f"Preempção por prioridade: {'ligada' if cpu.preempt else 'desligada'} | Semente: {cpu.seed} | "
              f"Prob. de syscall aleatória: {cpu.prob:g}/ms")
        if args:
            self.log("SCHED_CONFIG", f"{cpu.alg} q={cpu.quantum} seed={cpu.seed}")

    def cmd_compare_sched(self, args):
        _, opts = parse_opts(args, valued=("--quantum", "-q", "--algs", "-a"))
        if not self.cpu.pcbs:
            raise FSError("nenhum processo no escalonador")
        q = parse_ms(opts.get("--quantum", opts.get("-q", str(self.cpu.quantum))), "quantum")
        algs = [get_sched(a) for a in opts.get("--algs", opts.get("-a", "fcfs,rr,priority,priority_rr")).split(",")]
        rows = []
        for alg in algs:
            cpu = CPU(alg, q, self.cpu.seed, self.cpu.prob, self.cpu.preempt)
            for pcb in self.cpu.pcbs:
                if pcb.killed:
                    continue
                clone = copy.copy(pcb)
                clone.loc = 0
                cpu.pcbs.append(clone)
                n = clone.threads
                base, extra = divmod(clone.burst, n)
                clone.tasks = [Task(clone, i + 1, base + (1 if i < extra else 0)) for i in range(n)]
                if clone.arrival <= 0:
                    for task in clone.tasks:
                        cpu.enqueue(task)
            cpu.run_all()
            _, agg = cpu.metrics()
            name = SCHED_ALGS[alg] + (f" (q={q}ms)" if cpu.uses_quantum else "")
            rows.append((name, f"{agg['awt']:.2f} ms", f"{agg['att']:.2f} ms", f"{agg['art']:.2f} ms",
                         cpu.switches, pct(agg["busy"], agg["span"]), f"{agg['span']} ms", agg["awt"]))
        print(self.s(f"[COMPARAÇÃO DE ESCALONADORES] mesma carga ({len(self.cpu.pcbs)} processo(s)), "
                     f"semente {self.cpu.seed}, sem efeitos colaterais na simulação", "1"))
        best = min(r[-1] for r in rows)
        table = [r[:-1] + ("<- menor AWT" if r[-1] == best else "",) for r in rows]
        for line in box(["Algoritmo", "AWT", "ATT", "Resposta", "Trocas", "CPU", "Duração", ""],
                        table, ["<", "^", "^", "^", "^", "^", "^", "<"]):
            print(line)

    def cmd_format(self, args):
        super().cmd_format(args)
        for pcb in self.cpu.pcbs:
            if pcb.kind != CRITICAL and not pcb.killed:
                self.cpu.kill(pcb, self.cpu.t)

    def cmd_mem_config(self, args):
        super().cmd_mem_config(args)
        for pcb in self.cpu.pcbs:
            if not pcb.killed and self.mem.find(pcb.pid) is None:
                self.cpu.kill(pcb, self.cpu.t)

    def cmd_demo5(self, args):
        from sec_sim import ADMIN, ROOT
        root = self.accounts[ROOT]
        self.accounts = {ROOT: root}
        self.groups = {ADMIN: 0}
        self.next_uid = self.next_gid = 1000
        self.stack, self.elevated, self.sudo_ok = [ROOT], False, set()
        self.cpu = CPU()
        self.cpu_base = self.mem.clock
        print("\n" + self.s(f"{' DEMONSTRAÇÃO ETAPA 5: PROCESSOS, THREADS E ESCALONAMENTO ':=^84}", "1;35"))
        return self.run_lines(DEMOS5)


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulador de Processos, Threads e Escalonamento - Etapa 5")
    p.add_argument("script", nargs="?")
    p.add_argument("-s", "--strategy", default="indexada")
    p.add_argument("-b", "--block-size", default="4KB")
    p.add_argument("-n", "--blocks", type=int, default=128)
    p.add_argument("--fit", choices=["first", "best", "worst"], default="first")
    p.add_argument("--media", choices=["hdd", "ssd"], default="hdd")
    p.add_argument("--alg", default="sstf")
    p.add_argument("--cylinders", type=int, default=200)
    p.add_argument("--raid", choices=list(RAID_LEVELS), default="none")
    p.add_argument("--disks", type=int, default=3)
    p.add_argument("--root-password", default="root")
    p.add_argument("--frames", type=int, default=32)
    p.add_argument("--page-size", default="4KB")
    p.add_argument("--swap-slots", type=int, default=64)
    p.add_argument("--replace", default="lru")
    p.add_argument("--scheduler", default="priority_rr")
    p.add_argument("--quantum", default="2ms")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--demo", action="store_true")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if os.name == "nt":
        os.system("")

    strategy = STRATEGY_ALIASES.get(a.strategy.lower())
    if strategy is None:
        p.error("estratégia inválida")
    try:
        replace = get_replace(a.replace)
        if replace not in LIVE_ALGS:
            p.error("--replace deve ser lru, fifo ou segunda_chance")
        mem = Memory(frames=a.frames, page=parse_size(a.page_size), slots=a.swap_slots)
        cpu = CPU(get_sched(a.scheduler), parse_ms(a.quantum, "quantum"), a.seed)
        fs = FileSystem(strategy, parse_size(a.block_size), a.blocks, a.fit)
        shell = ProcShell(fs, not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ,
                          root_password=a.root_password, cpu=cpu, mem=mem, replace=replace, media=a.media,
                          alg=get_alg(a.alg), cylinders=a.cylinders, level=RAID_LEVELS[a.raid], ndisks=a.disks)
    except FSError as e:
        p.error(str(e))

    if a.demo:
        shell.execute("demo5")
    elif a.script:
        shell.execute(f"run {shlex.quote(a.script)}")
    else:
        shell.repl()


if __name__ == "__main__":
    main()
