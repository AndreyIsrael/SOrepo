#!/usr/bin/env python3
import argparse
import math
import os
import re
import shlex
import sys

from fs_sim import STRATEGY_ALIASES, FileSystem, FSError, parse_opts, parse_size
from io_sim import RAID_LEVELS, get_alg
from sec_sim import ADMIN, ROOT, AccessDenied, SecShell, SecStorage, sha256

KB, MB = 1024, 1024 * 1024
SWAP_DIR, SWAP_PATH = "/swap", "/swap/pagefile.sys"
CRITICAL, NORMAL = "critical", "normal"
TYPE_ALIASES = {
    "critical": CRITICAL, "critico": CRITICAL, "crítico": CRITICAL, "kernel": CRITICAL,
    "normal": NORMAL, "user": NORMAL, "usuario": NORMAL, "usuário": NORMAL,
}
ALG_NAMES = {"lru": "LRU", "fifo": "FIFO", "segunda_chance": "Segunda Chance", "otimo": "Ótimo"}
ALG_LONG = {
    "lru": "LRU (Least Recently Used)",
    "fifo": "FIFO (First-In, First-Out)",
    "segunda_chance": "Segunda Chance (Relógio / Clock)",
    "otimo": "Ótimo de Belady (OPT)",
}
ALG_ALIASES = {
    "second_chance": "segunda_chance", "segunda-chance": "segunda_chance", "sc": "segunda_chance",
    "clock": "segunda_chance", "relogio": "segunda_chance", "relógio": "segunda_chance",
    "opt": "otimo", "optimal": "otimo", "ótimo": "otimo",
}
LIVE_ALGS = ("lru", "fifo", "segunda_chance")
WRITE_OPS = {"STORE", "STORE_DATA", "WRITE", "WRITE_DATA", "SAVE", "PUSH", "MOV_TO", "SET"}
MEM_EVENTS = {"create_process", "terminate_process", "execute_step", "translate_address", "run_trace",
              "memory_compact"}


def kb(n):
    if n % KB == 0:
        return f"{n // KB} KB"
    return f"{n / KB:.2f} KB"


def mb(n):
    s = f"{n / MB:.3f}".rstrip("0")
    return s + "0" if s.endswith(".") else s


def bar(frac, width=20):
    full = max(0, min(width, round(frac * width)))
    return "[" + "█" * full + "░" * (width - full) + "]"


def pct(a, b):
    return f"{100 * a / b if b else 0:.1f}%"


def get_replace(name):
    key = ALG_ALIASES.get(name.lower(), name.lower())
    if key not in ALG_NAMES:
        raise FSError(f"algoritmo desconhecido: {name} (use lru, fifo, segunda_chance ou otimo)")
    return key


def join_pt(items):
    items = [str(i) for i in items]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " e " + items[-1]


def simulate(alg, refs, n):
    frames, loaded, last, rbit = [None] * n, [0] * n, [0] * n, [0] * n
    hand, cols, faults = 0, [], []
    for t, p in enumerate(refs):
        if p in frames:
            i = frames.index(p)
            last[i], rbit[i] = t, 1
            faults.append(False)
        else:
            faults.append(True)
            if None in frames:
                i = frames.index(None)
            elif alg == "fifo":
                i = min(range(n), key=lambda k: loaded[k])
            elif alg == "lru":
                i = min(range(n), key=lambda k: last[k])
            elif alg == "otimo":
                def nxt(k):
                    try:
                        return refs.index(frames[k], t + 1)
                    except ValueError:
                        return math.inf
                i = max(range(n), key=nxt)
            else:
                while rbit[hand]:
                    rbit[hand] = 0
                    hand = (hand + 1) % n
                i, hand = hand, (hand + 1) % n
            frames[i], loaded[i], last[i], rbit[i] = p, t, t, 1
        cols.append(list(frames))
    return cols, faults


class SwapCorrupted(FSError):
    def __init__(self, proc, page):
        super().__init__(f"página {page.num} do PID {proc.pid} corrompida no swap")
        self.proc, self.page = proc, page


class Page:
    def __init__(self, num, used, slot):
        self.num, self.used, self.slot = num, used, slot
        self.present = False
        self.frame = None
        self.ref = 0
        self.dirty = False
        self.last = None
        self.loaded = None
        self.count = 0
        self.digest = None


class Proc:
    def __init__(self, pid, name, kind, owner, size, base=None, fixed=False):
        self.pid, self.name, self.kind, self.owner, self.size = pid, name, kind, owner, size
        self.base, self.fixed = base, fixed
        self.pages = []
        self.refs = self.faults = 0
        self.source = None

    @property
    def critical(self):
        return self.kind == CRITICAL

    def resident(self):
        return [p for p in self.pages if p.present]


class Memory:
    def __init__(self, reserved=4 * MB, kernel=1 * MB, frames=32, page=4 * KB, slots=32, fit="first",
                 tick=5, fault_cost=8):
        if kernel >= reserved:
            raise FSError("o núcleo base deve ser menor que a Área Reservada")
        if frames < 1 or slots < 1:
            raise FSError("molduras e slots de swap devem ser >= 1")
        if page < 512 or page & (page - 1):
            raise FSError("o tamanho da página deve ser potência de 2 e >= 512 B")
        if fit not in ("first", "best", "worst"):
            raise FSError("fit inválido (first, best ou worst)")
        self.reserved, self.kernel, self.nframes, self.page = reserved, kernel, frames, page
        self.nslots, self.fit, self.tick, self.fault_cost = slots, fit, tick, fault_cost
        self.reset()

    def reset(self):
        self.procs = {0: Proc(0, "Núcleo Base do SO", CRITICAL, ROOT, self.kernel, 0, fixed=True)}
        self.next_crit, self.next_pid = 1, 100
        self.clock = 0
        self.compactions = 0
        self.reset_virtual()

    def reset_virtual(self):
        for pid in [p for p, x in self.procs.items() if not x.critical]:
            del self.procs[pid]
        self.frames = [None] * self.nframes
        self.data = [None] * self.nframes
        self.slot_of = [None] * self.nslots
        self.hand = 0
        self.stats = dict.fromkeys(("refs", "hits", "faults", "evictions", "swap_out", "swap_in"), 0)

    @property
    def dynamic(self):
        return self.nframes * self.page

    def critical(self):
        return sorted((p for p in self.procs.values() if p.critical), key=lambda p: p.base)

    def normal(self):
        return sorted((p for p in self.procs.values() if not p.critical), key=lambda p: p.pid)

    def holes(self):
        out, cur = [], 0
        for p in self.critical():
            if p.base > cur:
                out.append((cur, p.base - cur))
            cur = p.base + p.size
        if cur < self.reserved:
            out.append((cur, self.reserved - cur))
        return out

    def find_hole(self, size):
        fits = [h for h in self.holes() if h[1] >= size]
        if not fits:
            return None
        if self.fit == "best":
            return min(fits, key=lambda h: (h[1], h[0]))[0]
        if self.fit == "worst":
            return max(fits, key=lambda h: (h[1], -h[0]))[0]
        return fits[0][0]

    def free_frames(self):
        return [i for i, f in enumerate(self.frames) if f is None]

    def free_slots(self):
        return [i for i, s in enumerate(self.slot_of) if s is None]

    def frame_addr(self, f):
        return self.reserved + f * self.page

    def find(self, key):
        if key is None:
            return None
        for p in self.procs.values():
            if p.name == key or str(p.pid) == str(key):
                return p
        return None


class MemStorage(SecStorage):
    def file_bytes(self, node):
        area = getattr(node, "swap_area", None)
        if area is not None:
            return bytes(area[:node.size])
        return super().file_bytes(node)


HELP4 = """
ETAPA 4 - GERÊNCIA DE MEMÓRIA (alocação híbrida)
  Processos
    create_process --name N --size 512KB --type critical   Área Reservada: contígua, sem paginação (MODO_KERNEL)
    create_process --name N --size 10KB [--type normal]    Memória Virtual: paginação por demanda
    create_process --name N --file <arq> [--size X]        carrega a imagem de um arquivo (exige r+x)
    terminate_process --name N | --pid P                   encerra (críticos exigem MODO_KERNEL)
    ps                                                     lista os processos e onde estão na RAM
  Tradução e execução
    translate_address --process N --page P [--offset D] | --address 0x1A2B
    execute_step --process N --instruction "LOAD_DATA Página 2" [--value texto]
                                     (STORE_/WRITE_ marcam a página como modificada, bit M)
    run_trace --process N --refs "0 1 W2 0 3"   sequência de referências (W = escrita) em tabela
    page_table --process N                       tabela de páginas (P, moldura, R, M, slot de swap)
    tick <ms>                                    avança o relógio simulado
  Substituição de páginas
    replace_alg [lru|fifo|segunda_chance]        mostra/troca o algoritmo (troca exige MODO_KERNEL)
    compare_alg --refs "7 0 1 2 0 3" --frames 3 [--algs fifo,lru,segunda_chance,otimo]
  Fragmentação, compactação e ocupação
    memory_status [--reserved|--virtual|--frames|--swap]   análise de ocupação da RAM e do swap
    frag_report [--every N|off]                  relatório de fragmentação interna/externa (periódico)
    memory_compact --reserved                    compacta a Área Reservada (MODO_KERNEL)
    mem_config [--reserved 4MB] [--kernel 1MB] [--frames 32] [--page-size 4KB] [--swap-slots 32]
               [--fit first|best|worst] [--tick 5] [--force]   reconfigura a RAM (MODO_KERNEL)
    demo4                                        demonstração da etapa 4 (exemplos 4.1 e 4.2)
"""

DEMOS4 = [
    "# Preparação: disco, usuários e RAM (Área Reservada 4 MB + RAM Dinâmica de 8 molduras de 4 KB)",
    "io_log off",
    "format --strategy indexada --block-size 4KB --blocks 128",
    "groupadd devs",
    "useradd carlos --group devs --password Carlos@123",
    "mem_config --reserved 4MB --kernel 1MB --frames 8 --page-size 4KB --swap-slots 32 --fit first --force",
    "ls -l /swap",
    "# Exemplo 4.1 - Área Reservada: alocação contígua, fragmentação externa e compactação",
    "create_process --name \"Kernel_DiskDriver\" --size 512KB --type critical",
    "create_process --name \"Kernel_NetDriver\" --size 1024KB --type critical",
    "create_process --name \"Kernel_CryptoEngine\" --size 512KB --type critical",
    "terminate_process --name \"Kernel_NetDriver\"",
    "memory_status --reserved",
    "create_process --name \"Kernel_GPUDriver\" --size 1536KB --type critical",
    "memory_compact --reserved",
    "create_process --name \"Kernel_GPUDriver\" --size 1536KB --type critical",
    "translate_address --process Kernel_DiskDriver --offset 0x200",
    "# Exemplo 4.2 - Memória Virtual: paginação por demanda, fragmentação interna e LRU",
    "replace_alg lru",
    "create_process --name \"Shell_Usuario\" --size 8KB --type normal",
    "create_process --name \"Editor_Texto\" --size 8KB --type normal",
    "create_process --name \"Player_Musica\" --size 12KB --type normal",
    "execute_step --process Player_Musica --instruction \"STORE_DATA Página 0\" --value \"playlist=rock\"",
    "run_trace --process Shell_Usuario --refs \"0 1\"",
    "run_trace --process Editor_Texto --refs \"0 1\"",
    "run_trace --process Player_Musica --refs \"1\"",
    "create_process --name \"App_Navegador\" --size 10KB --type normal",
    "run_trace --process App_Navegador --refs \"0 1\"",
    "translate_address --process App_Navegador --page 1",
    "run_trace --process Shell_Usuario --refs \"0 1\"",
    "run_trace --process Editor_Texto --refs \"1 0\"",
    "io_log on",
    "execute_step --process App_Navegador --instruction \"LOAD_DATA Página 2\"",
    "io_log off",
    "page_table --process App_Navegador",
    "# Segunda Chance (relógio) e comparação dos algoritmos",
    "replace_alg segunda_chance",
    "execute_step --process Player_Musica --instruction \"LOAD_DATA Página 0\"",
    "run_trace --process Player_Musica --refs \"2 W1 0\"",
    "memory_status --frames",
    "compare_alg --refs \"7 0 1 2 0 3 0 4 2 3 0 3 2 1 2 0 1 7 0 1\" --frames 3",
    "compare_alg --refs \"1 2 3 4 1 2 5 1 2 3 4 5\" --frames 3 --algs fifo",
    "compare_alg --refs \"1 2 3 4 1 2 5 1 2 3 4 5\" --frames 4 --algs fifo",
    "# Integração com as etapas 1 a 3: arquivos executáveis, privilégios e integridade do swap",
    "replace_alg lru",
    "login --user carlos --password Carlos@123",
    "create /home/carlos/calc.bin --content \"CALC v1.0 :: rotina de soma e multiplicação\" --size 6KB",
    "chmod 640 /home/carlos/calc.bin",
    "create_process --name Calc --file /home/carlos/calc.bin",
    "chmod 750 /home/carlos/calc.bin",
    "create_process --name Calc --file /home/carlos/calc.bin",
    "execute_step --process Calc --instruction \"LOAD_DATA Página 1\"",
    "create_process --name \"Kernel_Spy\" --size 64KB --type critical",
    "terminate_process --name App_Navegador",
    "ps",
    "su root --password root",
    "page_table --process Calc",
    "disk_tamper /swap/pagefile.sys --block 10 --data \"codigo injetado no swap\"",
    "logout",
    "execute_step --process Calc --instruction \"LOAD_DATA Página 0\"",
    "# Relatórios de fragmentação e ocupação",
    "su root --password root",
    "frag_report",
    "frag_report --every 2",
    "terminate_process --name Shell_Usuario",
    "execute_step --process Player_Musica --instruction \"LOAD_DATA Página 2\"",
    "frag_report --every off",
    "memory_status",
    "logs --tail 8",
]


class MemShell(SecShell):
    storage_cls = MemStorage

    def __init__(self, fs, color=True, root_password="root", mem=None, replace="lru", **kw):
        self.mem = mem or Memory()
        self.alg = replace
        self.report_every = 0
        self.events = 0
        self.reports = 0
        self.no_swap = False
        super().__init__(fs, color, root_password, **kw)
        cmds = {
            "create_process": self.cmd_create_process, "terminate_process": self.cmd_terminate_process,
            "kill": self.cmd_terminate_process, "ps": self.cmd_ps,
            "translate_address": self.cmd_translate_address, "execute_step": self.cmd_execute_step,
            "run_trace": self.cmd_run_trace, "page_table": self.cmd_page_table, "tick": self.cmd_tick,
            "replace_alg": self.cmd_replace_alg, "compare_alg": self.cmd_compare_alg,
            "memory_status": self.cmd_memory_status, "frag_report": self.cmd_frag_report,
            "memory_compact": self.cmd_memory_compact, "mem_config": self.cmd_mem_config,
            "demo4": self.cmd_demo4,
        }
        self.commands.update({k: self.guard(k, self.counted(k, h)) for k, h in cmds.items()})

    def counted(self, name, handler):
        def run(args):
            result = handler(args)
            if name in MEM_EVENTS:
                self.events += 1
                if self.report_every and self.events % self.report_every == 0:
                    self.reports += 1
                    print()
                    print(self.s(f"[RELATÓRIO PERIÓDICO DE FRAGMENTAÇÃO #{self.reports}] "
                                 f"(a cada {self.report_every} evento(s) de memória | t = {self.mem.clock} ms)",
                                 "1;36"))
                    self.frag_summary()
            return result
        return run

    def needs_kernel(self, name, args):
        if name in ("memory_compact", "mem_config", "demo4"):
            return True
        if name == "replace_alg" and args:
            return True
        if name == "create_process":
            _, opts = parse_opts(args, valued=("--name", "-n", "--size", "-s", "--type", "-t", "--file", "-f"))
            return TYPE_ALIASES.get(opts.get("--type", opts.get("-t", "normal")).lower()) == CRITICAL
        return super().needs_kernel(name, args)

    def banner(self):
        print(self.s("Simulador de SO - Etapa 4: Gerência de Memória (integra as etapas 1, 2 e 3)", "1"))
        super().banner()
        m = self.mem
        print(f"RAM: Área Reservada {kb(m.reserved)} (núcleo {kb(m.kernel)}, contígua) + RAM Dinâmica "
              f"{m.nframes} molduras x {kb(m.page)} | Swap {m.nslots} slots em {SWAP_PATH} | "
              f"Substituição {ALG_NAMES[self.alg]}")
        print("Digite 'demo4' para a demonstração da etapa 4.\n")

    def cmd_help(self, args):
        super().cmd_help(args)
        print(HELP4)

    def bootstrap(self, fs):
        super().bootstrap(fs)
        if self.no_swap:
            return
        try:
            self.make_swap(fs)
        except FSError as e:
            print(f"Aviso: área de swap não criada ({e})")
        fs.cwd = fs.root

    def make_swap(self, fs):
        size = self.mem.nslots * self.mem.page
        self.sys_mkdir(fs, SWAP_DIR, mode=0o700)
        try:
            node = fs.read(SWAP_PATH)
            if node.size != size:
                fs.resize(SWAP_PATH, size)
        except FSError as e:
            if "não" not in str(e) and "inexist" not in str(e) and "encontr" not in str(e):
                raise
            self.stamp(fs)
            node = fs.create(SWAP_PATH, size)
        node.content = None
        node.swap_area = bytearray(size)
        self.sys_set(node, ROOT, ADMIN, 0o600)
        return node

    def swap_node(self):
        try:
            node = self.fs.resolve(SWAP_PATH)
        except FSError:
            return None
        return node if getattr(node, "swap_area", None) is not None else None

    def ensure_swap(self):
        node = self.swap_node()
        if node is None or node.size != self.mem.nslots * self.mem.page:
            node = self.make_swap(self.fs)
            self.storage.sync(f"criação da área de swap {SWAP_PATH}")
            print(f"Área de swap criada em {SWAP_PATH} ({self.mem.nslots} slots x {kb(self.mem.page)}).")
        return node

    def swap_in_use(self, node):
        swap = self.swap_node()
        if swap is None or not any(s is not None for s in self.mem.slot_of):
            return False
        while swap is not None:
            if swap is node:
                return True
            swap = swap.parent
        return False

    def swap_guard(self, path):
        try:
            node = self.fs.resolve(path)
        except FSError:
            return
        if self.swap_in_use(node):
            raise FSError(f"'{node.path}' contém a área de swap em uso pela memória virtual "
                          "(encerre os processos ou use mem_config --force)")

    def check_remove(self, path, recursive):
        self.swap_guard(path)
        super().check_remove(path, recursive)

    def cmd_mv(self, args):
        if args:
            self.swap_guard(args[0])
        super().cmd_mv(args)

    def cmd_write(self, args, append=False):
        if args:
            self.swap_guard(args[0])
        super().cmd_write(args, append)

    def cmd_resize(self, args):
        if args:
            self.swap_guard(args[0])
        super().cmd_resize(args)

    def cmd_format(self, args):
        had = bool(self.mem.normal())
        super().cmd_format(args)
        self.mem.reset_virtual()
        if had:
            print(self.s("Aviso: o swap foi recriado; processos da memória virtual foram encerrados.", "33"))

    def swap_range(self, node, slot):
        ps, bs = self.mem.page, self.fs.bs
        start, end = slot * ps, (slot + 1) * ps
        first, last = start // bs, (end - 1) // bs
        return node.blocks[first:last + 1], start - first * bs

    def swap_write(self, node, items, title):
        ps = self.mem.page
        for slot, data in items:
            node.swap_area[slot * ps:(slot + 1) * ps] = data
        self.storage.sync(title)

    def swap_read(self, node, slot, title):
        st = self.storage
        lbas, skip = self.swap_range(node, slot)
        if st.verbose:
            print(f"[E/S] '{title}' gerou {len(lbas)} requisição(ões) de leitura no disco lógico: "
                  + ", ".join(f"R {st.bnum(b)}" for b in lbas))
        data, ops, notes = st.array.read(lbas, st.label)
        for n in notes:
            print(n)
        st.deliver(ops, st.verbose)
        return b"".join(data[b] for b in lbas)[skip:skip + self.mem.page]

    def page_images(self, proc, blob):
        ps, out = self.mem.page, []
        for i in range(len(proc.pages)):
            used = proc.pages[i].used
            if blob is not None:
                chunk = blob[i * ps:i * ps + used]
            else:
                seed = f"[{proc.name}|PID {proc.pid}|pag {i}]".encode("utf-8")
                chunk = (seed * (used // len(seed) + 1))[:used]
            out.append(chunk.ljust(ps, b"\0"))
        return out

    def get_proc(self, pos, opts):
        key = (opts.get("--process") or opts.get("-p") or opts.get("--name") or opts.get("--pid")
               or (pos[0] if pos else None))
        if key is None:
            raise FSError("informe o processo com --process <nome|pid>")
        proc = self.mem.find(key)
        if proc is None:
            raise FSError(f"processo inexistente: '{key}' (veja 'ps')")
        return proc

    def require_proc(self, proc, what):
        if self.kernel or proc.owner == self.euser:
            return
        print(self.s("[SISTEMA DE SEGURANÇA - PROTEÇÃO DE MEMÓRIA]", "1"))
        print(f"Processo    : {proc.name} (PID {proc.pid}) | Dono: {proc.owner}")
        print(f"Ação Pedida : {what} por '{self.euser}' ({self.mode_name})")
        print(self.s(f"[NEGADO]: '{self.euser}' não pode realizar {what} em processo de outro usuário.", "31;1"))
        print("Tentativa não autorizada registrada nos logs do sistema.")
        self.log("MEM_NEGADO", f"{what} PID {proc.pid} ({proc.name})", "ALERTA")
        raise AccessDenied("acesso negado")

    def cmd_create_process(self, args):
        pos, opts = parse_opts(args, valued=("--name", "-n", "--size", "-s", "--type", "-t", "--file", "-f"))
        name = opts.get("--name", opts.get("-n")) or (pos[0] if pos else None)
        kind = TYPE_ALIASES.get(opts.get("--type", opts.get("-t", "normal")).lower())
        if not name:
            raise FSError("uso: create_process --name N --size 10KB [--type critical|normal] [--file arq]")
        if kind is None:
            raise FSError("tipo inválido (use critical ou normal)")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name) or name.isdigit():
            raise FSError("nome de processo inválido (letras, dígitos, _ . -)")
        if self.mem.find(name):
            raise FSError(f"já existe um processo chamado '{name}'")
        src = opts.get("--file", opts.get("-f"))
        blob, size = None, None
        if src:
            if kind == CRITICAL:
                raise FSError("processos críticos são carregados com --size (imagem residente do núcleo)")
            node = self.fs.read(src)
            self.require(node, "rx")
            if getattr(node, "cipher", None) is not None:
                raise FSError(f"'{node.path}' está criptografado e não pode ser carregado")
            blob = self.read_through(node)
            size = node.size
        if "--size" in opts or "-s" in opts:
            size = parse_size(opts.get("--size", opts.get("-s")))
            if blob is not None:
                blob = blob[:size]
        if not size:
            raise FSError("informe --size (> 0) ou --file")
        if kind == CRITICAL:
            return self.create_critical(name, size)
        return self.create_normal(name, size, blob, src)

    def create_critical(self, name, size):
        mem = self.mem
        base = mem.find_hole(size)
        if base is None:
            holes = mem.holes()
            free = sum(h[1] for h in holes)
            largest = max((h[1] for h in holes), default=0)
            print(self.s(f"[FALHA NA ALOCAÇÃO CONTÍGUA]: não existe bloco único de {kb(size)} livre na "
                         "Área Reservada.", "31;1"))
            print(f"Memória livre na Área Reservada: {kb(free)} em {len(holes)} fragmento(s) | "
                  f"Maior bloco contíguo: {kb(largest)}")
            if free >= size:
                print(self.s("Causa: FRAGMENTAÇÃO EXTERNA (há espaço total suficiente, mas não contíguo). "
                             "Execute 'memory_compact --reserved'.", "33"))
            else:
                print("Causa: espaço insuficiente na Área Reservada.")
            self.log("MEM_FALHA", f"crítico '{name}' {kb(size)} não alocado")
            return
        proc = Proc(mem.next_crit, name, CRITICAL, self.euser, size, base)
        mem.next_crit += 1
        mem.procs[proc.pid] = proc
        print(f"- Alocado de forma contígua na Área Reservada: [{mb(base)} MB até {mb(base + size)} MB] "
              f"({kb(size)})")
        print(self.s(f"  PID {proc.pid} | Base = 0x{base:08X} | Limite = 0x{size:08X} | sem paginação "
                     f"({mem.fit}-fit)", "2"))
        self.log("PROC_CRIAR", f"crítico PID {proc.pid} '{name}' [{mb(base)}-{mb(base + size)} MB]")

    def create_normal(self, name, size, blob, src):
        mem, ps = self.mem, self.mem.page
        n = -(-size // ps)
        free = mem.free_slots()
        if n > len(free):
            raise FSError(f"swap insuficiente: '{name}' precisa de {n} slot(s), há {len(free)} livre(s) "
                          f"em {SWAP_PATH}")
        node = self.ensure_swap()
        proc = Proc(mem.next_pid, name, NORMAL, self.euser, size)
        proc.source = src
        for i in range(n):
            proc.pages.append(Page(i, min(ps, size - i * ps), free[i]))
            mem.slot_of[free[i]] = (proc, proc.pages[i])
        mem.next_pid += 1
        mem.procs[proc.pid] = proc
        print(self.s("[CRIAÇÃO DE PROCESSO NÃO CRÍTICO - MEMÓRIA VIRTUAL]", "1"))
        print(f"Processo            : {name} (PID {proc.pid}, dono '{proc.owner}')"
              + (f" | imagem: {src}" if src else ""))
        print(f"Tamanho do Processo : {kb(size)} ({size} Bytes)")
        print(f"Tamanho da Página   : {kb(ps)} ({ps} Bytes)")
        pages = join_pt(range(n)) if n <= 6 else f"0 a {n - 1}"
        print(f"Cálculo de Páginas  : {kb(size)} / {kb(ps)} = {size / ps:g} -> Requer {n} Página"
              f"{'s' if n > 1 else ''} Lógica{'s' if n > 1 else ''} (Página{'s' if n > 1 else ''} {pages}).")
        print()
        print("--- ANÁLISE DE FRAGMENTAÇÃO INTERNA ---")
        full = [p for p in proc.pages if p.used == ps]
        if len(full) > 6:
            print(f"Páginas Lógicas 0 a {full[-1].num} : {ps} Bytes ocupados (100%) cada")
        else:
            for p in full:
                print(f"Página Lógica {p.num} : {ps} Bytes ocupados (100%)")
        last = proc.pages[-1]
        if last.used < ps:
            print(f"Página Lógica {last.num} : {last.used} Bytes ocupados ({last.used * 100 / ps:g}% de uso)")
            print(f"Fragmentação Interna Total: {ps - last.used} Bytes de desperdício na Página Lógica {last.num}.")
        else:
            print("Fragmentação Interna Total: 0 Bytes (tamanho múltiplo exato da página).")
        print("Status: Tabela de Páginas gerada sem alocar molduras na RAM (Alocação por demanda).")
        images = self.page_images(proc, blob)
        for p, img in zip(proc.pages, images):
            p.digest = sha256(img)
        self.swap_write(node, [(p.slot, img) for p, img in zip(proc.pages, images)],
                        f"create_process {name}: imagem no swap")
        print(f"Imagem gravada no Swap ({SWAP_PATH}): slot{'s' if n > 1 else ''} "
              f"{join_pt(p.slot for p in proc.pages)}.")
        self.log("PROC_CRIAR", f"PID {proc.pid} '{name}' {kb(size)} ({n} páginas)")

    def release(self, proc, node=None):
        mem = self.mem
        frames, slots = [], []
        for p in proc.pages:
            if p.present:
                mem.frames[p.frame] = None
                mem.data[p.frame] = None
                frames.append(p.frame)
            mem.slot_of[p.slot] = None
            slots.append(p.slot)
        del mem.procs[proc.pid]
        node = node or self.swap_node()
        if node is not None and slots:
            self.swap_write(node, [(s, bytes(mem.page)) for s in slots], f"liberação do swap de {proc.name}")
        return frames, slots

    def cmd_terminate_process(self, args):
        pos, opts = parse_opts(args, valued=("--name", "-n", "--pid", "--process", "-p"))
        proc = self.get_proc(pos, opts)
        if proc.fixed:
            raise FSError("o Núcleo Base do SO não pode ser encerrado")
        if proc.critical:
            if not self.kernel:
                self.deny_privilege(f"terminate_process --name {proc.name}")
                return
            del self.mem.procs[proc.pid]
            print(self.s("[ENCERRAMENTO DE PROCESSO CRÍTICO]", "1") + f" Processo '{proc.name}' finalizado.")
            print(f"Área de {kb(proc.size)} no intervalo [{mb(proc.base)} MB a {mb(proc.base + proc.size)} MB] "
                  "liberada na Área Reservada da RAM.")
            self.log("PROC_FIM", f"crítico PID {proc.pid} '{proc.name}'")
            return
        self.require_proc(proc, "encerramento")
        frames, slots = self.release(proc)
        print(self.s("[ENCERRAMENTO DE PROCESSO]", "1") + f" Processo '{proc.name}' (PID {proc.pid}) finalizado.")
        print(f"Molduras liberadas na RAM Dinâmica: {join_pt(frames) if frames else 'nenhuma (sem páginas residentes)'}")
        print(f"Slots de swap liberados e zerados : {join_pt(slots)}")
        self.log("PROC_FIM", f"PID {proc.pid} '{proc.name}'")

    def cmd_ps(self, args):
        mem = self.mem
        print(self.s(f"[PROCESSOS] t = {mem.clock} ms | substituição: {ALG_NAMES[self.alg]}", "1"))
        print(f"{'PID':>4}  {'PROCESSO':<20} {'TIPO':<8} {'DONO':<8} {'TAMANHO':>9}  {'LOCALIZAÇÃO':<34} FAULTS")
        for p in sorted(mem.procs.values(), key=lambda x: x.pid):
            if p.critical:
                where = f"Reservada [{mb(p.base)} - {mb(p.base + p.size)} MB]"
                faults = "-"
                kind = "crítico"
            else:
                where = f"Virtual: {len(p.resident())}/{len(p.pages)} páginas na RAM"
                faults = f"{p.faults}/{p.refs}"
                kind = "normal"
            print(f"{p.pid:>4}  {p.name:<20} {kind:<8} {p.owner:<8} {kb(p.size):>9}  {where:<34} {faults}")

    def logical(self, proc, pos, opts, instr=""):
        ps = self.mem.page
        try:
            if "--address" in opts or "-a" in opts:
                addr = int(opts.get("--address", opts.get("-a")), 0)
                num, off = divmod(addr, ps)
            else:
                m = re.search(r"(?:p[áa]g(?:ina)?|page)\s*(\d+)", instr, re.I)
                a = re.search(r"0x[0-9a-fA-F]+", instr)
                if "--page" in opts:
                    num = int(opts["--page"], 0)
                elif m:
                    num = int(m.group(1))
                elif a:
                    num, off = divmod(int(a.group(0), 16), ps)
                    return self.check_logical(proc, num, off)
                else:
                    raise FSError("informe --page P, --address 0x... ou 'Página P' na instrução")
                off = int(opts.get("--offset", "0"), 0)
        except ValueError:
            raise FSError("endereço/página/deslocamento inválido")
        return self.check_logical(proc, num, off)

    def check_logical(self, proc, num, off):
        ps = self.mem.page
        if not 0 <= off < ps:
            raise FSError(f"deslocamento deve estar entre 0 e {ps - 1}")
        if not 0 <= num < len(proc.pages):
            self.log("SEGFAULT", f"PID {proc.pid} página {num}", "ALERTA")
            raise FSError(f"SEGMENTATION FAULT: página lógica {num} fora do espaço de endereçamento de "
                          f"'{proc.name}' (páginas 0..{len(proc.pages) - 1})")
        return num, off

    def contig_offset(self, proc, opts, instr=""):
        raw = opts.get("--offset") or opts.get("--address") or opts.get("-a")
        if raw is None:
            m = re.search(r"0x[0-9a-fA-F]+|\b\d+\b", instr)
            raw = m.group(0) if m else "0"
        try:
            off = int(raw, 0)
        except ValueError:
            raise FSError("deslocamento inválido")
        if not 0 <= off < proc.size:
            self.log("SEGFAULT", f"PID {proc.pid} deslocamento {off}", "ALERTA")
            raise FSError(f"VIOLAÇÃO DE LIMITE: deslocamento 0x{off:X} >= limite 0x{proc.size:X} de '{proc.name}'")
        return off

    def translate_contig(self, proc, off):
        print(self.s("[TRADUÇÃO DE ENDEREÇO: REGISTRADORES BASE/LIMITE (ÁREA RESERVADA)]", "1"))
        print(f"Processo crítico '{proc.name}' (PID {proc.pid}) é contíguo e sem paginação: não há page fault.")
        print(f"Verificação     : deslocamento 0x{off:X} < limite 0x{proc.size:X} -> OK")
        print(f"Endereço Físico : base 0x{proc.base:08X} + 0x{off:X} = 0x{proc.base + off:08X}")

    def cmd_translate_address(self, args):
        pos, opts = parse_opts(args, valued=("--process", "-p", "--name", "--pid", "--page", "--offset",
                                             "--address", "-a"))
        proc = self.get_proc(pos, opts)
        self.require_proc(proc, "acesso à memória")
        if proc.critical:
            self.mem.clock += self.mem.tick
            return self.translate_contig(proc, self.contig_offset(proc, opts))
        num, off = self.logical(proc, pos, opts)
        pg = proc.pages[num]
        print(self.s("[TRADUÇÃO DE ENDEREÇO: PÁGINA LÓGICA -> MOLDURA FÍSICA]", "1"))
        if pg.present:
            print(f"Solicitação: Página Lógica {num} -> Mapeada na Moldura Física {pg.frame} (RAM Dinâmica) "
                  + self.s("[HIT]", "32;1"))
        else:
            print(f"Solicitação: Página Lógica {num} -> bit de presença = 0 (não está na RAM) "
                  + self.s("[MISS]", "31;1"))
        info = self.safe_access(proc, num, off)
        if info is None:
            return
        ps = self.mem.page
        print(f"Endereço Lógico : 0x{num * ps + off:06X} = Página {num} x {ps} + deslocamento {off}")
        print(f"Endereço Físico : 0x{info['phys']:08X} = base da Moldura {info['frame']} "
              f"(0x{self.mem.frame_addr(info['frame']):08X}) + deslocamento {off}")

    def cmd_execute_step(self, args):
        pos, opts = parse_opts(args, valued=("--process", "-p", "--name", "--pid", "--instruction", "-i",
                                             "--page", "--offset", "--address", "-a", "--value", "-v"))
        proc = self.get_proc(pos, opts)
        instr = opts.get("--instruction", opts.get("-i")) or " ".join(pos[1:]) or "LOAD_DATA"
        op = instr.split()[0].upper()
        write = op in WRITE_OPS
        self.require_proc(proc, "execução de instruções")
        mem = self.mem
        print(self.s("[CPU - REFERÊNCIA DE MEMÓRIA EM EXECUÇÃO]", "1"))
        if proc.critical:
            off = self.contig_offset(proc, opts, " ".join(instr.split()[1:]))
            mem.clock += mem.tick
            print(f"{proc.name} (crítico) executa {op} no deslocamento 0x{off:X}...")
            print(f"- Tradução Base/Limite: 0x{proc.base:08X} + 0x{off:X} = 0x{proc.base + off:08X} "
                  "(residente na Área Reservada, sem consulta à tabela de páginas)")
            print(f"Relógio: t = {mem.clock} ms")
            return
        num, off = self.logical(proc, pos, opts, instr)
        pg = proc.pages[num]
        print(f"{proc.name} requisita acesso à Página Lógica {num}...")
        if pg.present:
            print(f"- Consulta Tabela de Páginas -> Página Lógica {num} presente na Moldura Física {pg.frame} "
                  + self.s("[HIT]", "32;1"))
        else:
            print(f"- Consulta Tabela de Páginas -> Página Lógica {num} NÃO ESTÁ NA RAM!")
        value = opts.get("--value", opts.get("-v"))
        if write and value is None:
            value = f"dado@{mem.clock + mem.tick}ms"
        info = self.safe_access(proc, num, off, write, value)
        if info is None:
            return
        if write:
            print(f"- {op} concluída: {info['wrote']} byte(s) gravados em 0x{info['phys']:08X} "
                  f"(Moldura {info['frame']}, deslocamento {off}) | bit M = 1 (página modificada).")
        else:
            raw = bytes(mem.data[info["frame"]][off:off + 32]).rstrip(b"\0")
            text = "".join(ch if ch.isprintable() else "." for ch in raw.decode("utf-8", "replace"))
            print(f"- {op} concluída: leitura em 0x{info['phys']:08X} (Moldura {info['frame']}) -> \"{text}\"")
        print(f"Relógio: t = {mem.clock} ms")

    def safe_access(self, proc, num, off=0, write=False, value=None, verbose=True):
        try:
            return self.access(proc, num, off, write, value, verbose)
        except SwapCorrupted as e:
            self.corrupted(e.proc, e.page)
            return None

    def access(self, proc, num, off=0, write=False, value=None, verbose=True):
        mem = self.mem
        say = print if verbose else (lambda *a, **k: None)
        pg = proc.pages[num]
        mem.clock += mem.tick
        mem.stats["refs"] += 1
        proc.refs += 1
        info = {"hit": pg.present, "victim": None, "out": False, "wrote": 0}
        if pg.present:
            mem.stats["hits"] += 1
        else:
            mem.stats["faults"] += 1
            proc.faults += 1
            self.page_fault(proc, pg, say, info)
            mem.clock += mem.fault_cost
        f = pg.frame
        pg.ref, pg.last = 1, mem.clock
        pg.count += 1
        if write:
            data = (value or "").encode("utf-8")[:mem.page - off]
            mem.data[f][off:off + len(data)] = data
            pg.dirty = True
            info["wrote"] = len(data)
        info["frame"] = f
        info["phys"] = mem.frame_addr(f) + off
        return info

    def page_fault(self, proc, pg, say, info):
        mem = self.mem
        say()
        say(self.s(f"[PAGE FAULT DETECTADO]: Página Lógica {pg.num} ausente na RAM!", "31;1"))
        free = mem.free_frames()
        if free:
            f = free[0]
            say(f"- Moldura Física {f} livre na RAM Dinâmica ({len(free)} livre(s)): sem necessidade de substituição.")
        else:
            say(f"Memória RAM cheia. Executando Substituição de Página (Algoritmo {ALG_NAMES[self.alg]}):")
            f = self.pick_victim(say)
            vp, vpg = mem.frames[f]
            info["victim"] = f"PID {vp.pid}/pág {vpg.num}" + (" (M=1)" if vpg.dirty else "")
            info["out"] = vpg.dirty
            self.evict(f, say)
        node = self.swap_node()
        if node is None:
            raise FSError(f"área de swap {SWAP_PATH} indisponível")
        say(f"- Carregando Página Lógica {pg.num} do {proc.name} na Moldura Física {f} (RAM Dinâmica) "
            f"a partir do Swap (slot {pg.slot}).")
        blob = self.swap_read(node, pg.slot, f"swap-in {proc.name} pág {pg.num}")
        mem.stats["swap_in"] += 1
        if sha256(blob) != pg.digest:
            raise SwapCorrupted(proc, pg)
        mem.frames[f] = (proc, pg)
        mem.data[f] = bytearray(blob)
        pg.present, pg.frame, pg.loaded, pg.dirty = True, f, mem.clock, False
        say(f"- Tabela de Páginas atualizada: Página Lógica {pg.num} ---> Moldura Física {f}.")

    def pick_victim(self, say):
        mem = self.mem
        occ = [(f, p, pg) for f, (p, pg) in enumerate(mem.frames)]
        if self.alg in ("lru", "fifo"):
            attr = "last" if self.alg == "lru" else "loaded"
            order = sorted(occ, key=lambda x: (getattr(x[2], attr), x[0]))
            listing = ", ".join(f"PID {p.pid}/pág {pg.num}={mem.clock - getattr(pg, attr)}ms"
                                for _, p, pg in order[:5])
            f, p, pg = order[0]
            age = mem.clock - getattr(pg, attr)
            if self.alg == "lru":
                say(f"- Tempo desde o último acesso: {listing}{' ...' if len(order) > 5 else ''}")
                say(f"- Analisando histórico de acesso: Página Lógica {pg.num} do PID {p.pid} não é usada há "
                    f"{age}ms (Mais antiga).")
            else:
                say(f"- Fila FIFO (tempo na RAM): {listing}{' ...' if len(order) > 5 else ''}")
                say(f"- Página Lógica {pg.num} do PID {p.pid} é a primeira da fila (carregada há {age}ms).")
            return f
        start, lines, n = mem.hand, [], mem.nframes
        while True:
            p, pg = mem.frames[mem.hand]
            if pg.ref:
                lines.append(f"  Moldura {mem.hand:>3}: PID {p.pid}/pág {pg.num} R=1 -> recebe segunda chance (R := 0)")
                pg.ref = 0
                mem.hand = (mem.hand + 1) % n
                continue
            lines.append(f"  Moldura {mem.hand:>3}: PID {p.pid}/pág {pg.num} R=0 -> VÍTIMA")
            f = mem.hand
            mem.hand = (mem.hand + 1) % n
            break
        say(f"- Ponteiro do relógio parte da Moldura {start}:")
        if len(lines) > 8:
            lines = lines[:5] + [f"  ... ({len(lines) - 6} moldura(s) com R=1 zeradas)"] + lines[-1:]
        for line in lines:
            say(line)
        say(f"- Página Lógica {pg.num} do PID {p.pid} escolhida (bit de referência R=0).")
        return f

    def evict(self, f, say):
        mem = self.mem
        p, pg = mem.frames[f]
        if pg.dirty:
            say(f"- Removendo Página Lógica {pg.num} do PID {p.pid} da RAM -> Salvando no Swap (Disco) "
                f"[slot {pg.slot}, bit M=1].")
            data = bytes(mem.data[f])
            pg.digest = sha256(data)
            self.swap_write(self.swap_node(), [(pg.slot, data)], f"swap-out PID {p.pid} pág {pg.num}")
            mem.stats["swap_out"] += 1
        else:
            say(f"- Removendo Página Lógica {pg.num} do PID {p.pid} da RAM -> bit M=0: a cópia no Swap "
                f"(slot {pg.slot}) já está atualizada, nenhuma escrita necessária.")
        pg.present, pg.frame, pg.ref, pg.dirty = False, None, 0, False
        mem.frames[f] = None
        mem.data[f] = None
        mem.stats["evictions"] += 1

    def corrupted(self, proc, pg):
        print(self.s("[INTEGRIDADE DO SWAP - FALHA]", "31;1"))
        print(self.s(f"O hash SHA-256 da Página Lógica {pg.num} do PID {proc.pid} lida do slot {pg.slot} não "
                     "confere com o registrado na última gravação legítima.", "31"))
        print("A página foi alterada fora do sistema (escrita direta no disco). Carga abortada.")
        frames, slots = self.release(proc)
        print(self.s(f"Processo '{proc.name}' (PID {proc.pid}) encerrado (SIGBUS) para impedir o uso de "
                     f"código/dados adulterados. Slots {join_pt(slots)} zerados.", "31;1"))
        self.log("SWAP_CORROMPIDO", f"PID {proc.pid} pág {pg.num} slot {pg.slot}", "ALERTA")

    def cmd_run_trace(self, args):
        pos, opts = parse_opts(args, valued=("--process", "-p", "--name", "--pid", "--refs", "-r"))
        proc = self.get_proc(pos, opts)
        self.require_proc(proc, "execução de instruções")
        if proc.critical:
            raise FSError("run_trace se aplica a processos da memória virtual")
        raw = opts.get("--refs", opts.get("-r")) or " ".join(pos[1:])
        refs = []
        for tok in re.split(r"[\s,]+", raw.strip()):
            m = re.fullmatch(r"([rRwW]?)(\d+)", tok)
            if not m:
                raise FSError(f"referência inválida: '{tok}' (use 3, R3 ou W3)")
            refs.append((m.group(1).upper() == "W", int(m.group(2))))
        if not refs:
            raise FSError("uso: run_trace --process N --refs \"0 1 W2\"")
        for _, num in refs:
            self.check_logical(proc, num, 0)
        mem, st = self.mem, self.storage
        print(self.s(f"[EXECUÇÃO DE TRAÇO DE REFERÊNCIAS] {proc.name} (PID {proc.pid}) | algoritmo "
                     f"{ALG_NAMES[self.alg]} | {mem.nframes} molduras", "1"))
        print(f"{'#':>3}  {'t(ms)':>6}  {'REF':<5} {'RESULTADO':<11} {'MOLDURA':>7}  {'VÍTIMA':<22} SWAP")
        old, st.verbose = st.verbose, False
        faults = 0
        try:
            for i, (w, num) in enumerate(refs, 1):
                info = self.safe_access(proc, num, 0, w, f"w@{mem.clock + mem.tick}ms" if w else None, False)
                if info is None:
                    break
                faults += not info["hit"]
                io = "-" if info["hit"] else ("out+in" if info["out"] else "in")
                res = self.s("HIT", "32") + " " * 8 if info["hit"] else self.s("PAGE FAULT", "31") + " "
                print(f"{i:>3}  {mem.clock:>6}  {('W' if w else 'R') + str(num):<5} {res}"
                      f"{info['frame']:>7}  {info['victim'] or '-':<22} {io}")
        finally:
            st.verbose = old
        print(f"Resumo: {len(refs)} referência(s), {faults} page fault(s) ({pct(faults, len(refs))}), "
              f"{len(refs) - faults} hit(s) | residentes: {len(proc.resident())}/{len(proc.pages)} páginas")

    def cmd_page_table(self, args):
        pos, opts = parse_opts(args, valued=("--process", "-p", "--name", "--pid"))
        proc = self.get_proc(pos, opts)
        self.require_proc(proc, "consulta à tabela de páginas")
        if proc.critical:
            print(f"'{proc.name}' é crítico (Área Reservada, contíguo): sem tabela de páginas. "
                  f"Base 0x{proc.base:08X} | Limite 0x{proc.size:08X}")
            return
        mem = self.mem
        print(self.s(f"[TABELA DE PÁGINAS] {proc.name} (PID {proc.pid}) | {len(proc.pages)} páginas de "
                     f"{kb(mem.page)} | t = {mem.clock} ms", "1"))
        print(f"{'PÁG':>4}  {'P':>1}  {'MOLDURA':>7}  {'END. FÍSICO':>11}  {'R':>1}  {'M':>1}  {'SWAP':>4}  "
              f"{'USO':>11}  {'ÚLT. ACESSO':>11}  ACESSOS")
        for p in proc.pages:
            frame = str(p.frame) if p.present else "-"
            phys = f"0x{mem.frame_addr(p.frame):08X}" if p.present else "-"
            last = f"{mem.clock - p.last} ms atrás" if p.last is not None else "nunca"
            use = f"{p.used}B {p.used * 100 // mem.page}%"
            print(f"{p.num:>4}  {int(p.present):>1}  {frame:>7}  {phys:>11}  {p.ref:>1}  {int(p.dirty):>1}  "
                  f"{p.slot:>4}  {use:>11}  {last:>11}  {p.count}")
        print(f"Page faults: {proc.faults} em {proc.refs} referência(s) ({pct(proc.faults, proc.refs)})")

    def cmd_tick(self, args):
        try:
            ms = int(args[0]) if args else self.mem.tick
        except ValueError:
            raise FSError("uso: tick <ms>")
        if ms < 0:
            raise FSError("o relógio só avança")
        self.mem.clock += ms
        self.ok(f"Relógio avançou {ms} ms: t = {self.mem.clock} ms")

    def cmd_replace_alg(self, args):
        if not args:
            print(f"Algoritmo de substituição atual: {ALG_LONG[self.alg]}")
            print("Disponíveis na simulação: " + ", ".join(LIVE_ALGS) + " | 'otimo' apenas em compare_alg")
            return
        alg = get_replace(args[0])
        if alg not in LIVE_ALGS:
            raise FSError("o algoritmo Ótimo exige conhecer o futuro: use-o em 'compare_alg'")
        self.alg = alg
        if alg == "segunda_chance":
            self.mem.hand = 0
        self.ok(f"Algoritmo de substituição de páginas: {ALG_LONG[alg]}")
        self.log("MEM_ALG", ALG_NAMES[alg])

    def cmd_compare_alg(self, args):
        _, opts = parse_opts(args, valued=("--refs", "-r", "--frames", "-f", "--algs", "-a"))
        raw = opts.get("--refs", opts.get("-r"))
        if not raw:
            raise FSError("uso: compare_alg --refs \"7 0 1 2 0 3\" --frames 3 [--algs fifo,lru,segunda_chance,otimo]")
        try:
            refs = [int(re.sub(r"^[rRwW]", "", t)) for t in re.split(r"[\s,]+", raw.strip())]
            n = int(opts.get("--frames", opts.get("-f", "3")))
        except ValueError:
            raise FSError("referências e --frames devem ser inteiros")
        if n < 1:
            raise FSError("--frames deve ser >= 1")
        algs = [get_replace(a) for a in opts.get("--algs", opts.get("-a", "fifo,lru,segunda_chance,otimo")).split(",")]
        width = max(2, max(len(str(r)) for r in refs)) + 1
        results = []
        for alg in algs:
            cols, faults = simulate(alg, refs, n)
            total = sum(faults)
            results.append((alg, total))
            print(self.s(f"--- {ALG_LONG[alg]} | {n} molduras ---", "1"))
            print("Ref       :" + "".join(f"{r:>{width}}" for r in refs))
            for i in range(n):
                print(f"Moldura {i:<2}:" + "".join(f"{'' if c[i] is None else c[i]:>{width}}" for c in cols))
            print("Falta     :" + "".join(self.s(f"{'F':>{width}}", "31") if f else f"{'.':>{width}}" for f in faults))
            print(f"Total: {total} page faults em {len(refs)} referências (taxa {pct(total, len(refs))})\n")
        if len(results) > 1:
            best = min(t for _, t in results)
            print(self.s("RANKING (menos page faults é melhor)", "1"))
            for alg, total in sorted(results, key=lambda x: x[1]):
                mark = " <- melhor" if total == best else ""
                print(f"  {ALG_NAMES[alg]:<15} {total:>3} faults  {bar(total / len(refs), 20)} "
                      f"{pct(total, len(refs))}{mark}")

    def reserved_map(self, title=None):
        mem = self.mem
        if title is None:
            title = f"--- MAPA DA ÁREA CRÍTICA/RESERVADA DA RAM (Total: {mb(mem.reserved)} MB - Alocação Fixa) ---"
        print(self.s(title, "1"))
        holes = mem.holes()
        rows = [(p.base, p.size, p.name, True) for p in mem.critical()] + [(h[0], h[1], None, False) for h in holes]
        rows.sort()
        width = max(len(r[2]) for r in rows if r[2]) if any(r[2] for r in rows) else 20
        width = max(width, 20)
        k = 0
        for start, size, name, used in rows:
            span = f"[{mb(start)} MB - {mb(start + size)} MB]"
            if used:
                print(f"{span} : {name:<{width}} ({kb(size)}) " + self.s("[OCUPADO]", "34"))
            else:
                k += 1
                label = f"FRAGMENTO LIVRE {k}" if len(holes) > 1 else "Bloco Livre Contíguo"
                tag = "[LIVRE - LACUNA]" if len(holes) > 1 else "[LIVRE]"
                print(f"{span} : {label:<{width}} ({kb(size)}) " + self.s(tag, "33" if len(holes) > 1 else "32"))

    def external_diag(self):
        mem = self.mem
        holes = mem.holes()
        free = sum(h[1] for h in holes)
        largest = max((h[1] for h in holes), default=0)
        print(self.s("--- DIAGNÓSTICO DE FRAGMENTAÇÃO EXTERNA ---", "1"))
        print(f"Total de Memória Livre na Área Reservada : {kb(free)} ({mb(free)} MB)")
        print(f"Maior Bloco Contíguo Disponível          : {kb(largest)} ({mb(largest)} MB)")
        if len(holes) > 1:
            print(f"Fragmentação Externa Detectada           : " + self.s(f"SIM ({len(holes)} fragmentos não contíguos)", "31;1"))
            print(f"Índice de Fragmentação (1 - maior/livre) : {pct(free - largest, free)}")
            step = 512 * KB
            req = (largest // step + 1) * step
            if req > free:
                req = free
            print(f"Status: Uma requisição contígua de {kb(req)} falhará por ausência de bloco único.")
        else:
            print("Fragmentação Externa Detectada           : " + self.s("NÃO", "32;1")
                  + (" (espaço livre em bloco único)" if holes else " (área cheia)"))

    def internal_rows(self):
        ps = self.mem.page
        rows = []
        for p in self.mem.normal():
            last = p.pages[-1]
            rows.append((p, len(p.pages) * ps, ps - last.used, last))
        return rows

    def frag_summary(self):
        mem = self.mem
        holes = mem.holes()
        free = sum(h[1] for h in holes)
        largest = max((h[1] for h in holes), default=0)
        rows = self.internal_rows()
        alloc = sum(r[1] for r in rows)
        waste = sum(r[2] for r in rows)
        resident = [(f, p, pg) for f, x in enumerate(mem.frames) if x for p, pg in [x]]
        rwaste = sum(mem.page - pg.used for _, _, pg in resident)
        print(f"  Externa (Área Reservada): {len(holes)} lacuna(s), {kb(free)} livres, maior bloco {kb(largest)}"
              + (" -> " + self.s("FRAGMENTADA", "31") if len(holes) > 1 else " -> ok"))
        print(f"  Interna (Memória Virtual): {waste} B desperdiçados em {kb(alloc)} de páginas "
              f"({pct(waste, alloc)}) | nas molduras ocupadas: {rwaste} B ({pct(rwaste, len(resident) * mem.page)})")

    def cmd_frag_report(self, args):
        _, opts = parse_opts(args, valued=("--every",))
        if "--every" in opts:
            v = opts["--every"].lower()
            if v in ("off", "0"):
                self.report_every = 0
                self.ok("Relatório periódico de fragmentação desativado.")
                return
            try:
                self.report_every = int(v)
            except ValueError:
                raise FSError("uso: frag_report --every N|off")
            if self.report_every < 1:
                raise FSError("N deve ser >= 1")
            self.events = 0
            self.ok(f"Relatório periódico de fragmentação a cada {self.report_every} evento(s) de memória "
                    f"({', '.join(sorted(MEM_EVENTS))}).")
            return
        mem = self.mem
        print(self.s(f"[RELATÓRIO DE FRAGMENTAÇÃO DA MEMÓRIA] t = {mem.clock} ms", "1;36"))
        print()
        self.reserved_map()
        print()
        self.external_diag()
        print()
        print(self.s(f"--- FRAGMENTAÇÃO INTERNA (Memória Virtual, páginas de {kb(mem.page)}) ---", "1"))
        rows = self.internal_rows()
        if not rows:
            print("Nenhum processo na memória virtual.")
        for p, alloc, waste, last in rows:
            state = (f"residente na Moldura {last.frame}" if last.present else "no swap")
            print(f"PID {p.pid:<4} {p.name:<18} {kb(p.size):>9} em {len(p.pages)} pág. -> última (pág {last.num}) "
                  f"usa {last.used}/{mem.page} B | desperdício {waste} B ({state})")
        alloc = sum(r[1] for r in rows)
        waste = sum(r[2] for r in rows)
        if rows:
            print(f"Fragmentação Interna Total: {waste} Bytes em {kb(alloc)} de páginas alocadas ({pct(waste, alloc)}).")
        under = [(f, p, pg) for f, x in enumerate(mem.frames) if x for p, pg in [x] if pg.used < mem.page]
        if under:
            print("Molduras subutilizadas na RAM: " + ", ".join(
                f"M{f} (PID {p.pid}/pág {pg.num}: {pg.used * 100 // mem.page}%)" for f, p, pg in under))
        print("Fragmentação externa na RAM Dinâmica: inexistente (paginação usa molduras não contíguas).")

    def cmd_memory_compact(self, args):
        if "--virtual" in args:
            print("A RAM Dinâmica é paginada: qualquer moldura livre serve, então não há fragmentação externa "
                  "a compactar. A compactação se aplica à Área Reservada (--reserved).")
            return
        mem = self.mem
        print(self.s("[EXECUTANDO COMPACTAÇÃO DA ÁREA RESERVADA DA RAM]", "1"))
        print("Realocando blocos contíguos para eliminar a fragmentação externa...")
        cur, moved, copied = 0, 0, 0
        for p in mem.critical():
            if p.fixed:
                cur = p.base + p.size
                continue
            if p.base != cur:
                print(f"- Mapeamento de '{p.name}': [{mb(p.base)} MB a {mb(p.base + p.size)} MB] -> Ajustado para: "
                      f"[{mb(cur)} MB a {mb(cur + p.size)} MB]  (registrador Base 0x{cur:08X})")
                p.base = cur
                moved += 1
                copied += p.size
            cur += p.size
        if not moved:
            print("- Nenhum bloco precisou ser movido: a área já está compactada.")
        mem.compactions += 1
        print()
        self.reserved_map("--- MAPA APÓS COMPACTAÇÃO ---")
        largest = max((h[1] for h in mem.holes()), default=0)
        print(f"Resultado: Fragmentação externa eliminada. Maior bloco contíguo: {kb(largest)}.")
        if moved:
            print(self.s(f"Custo: {moved} processo(s) realocado(s), {kb(copied)} copiados na RAM.", "2"))
        self.log("MEM_COMPACT", f"{moved} bloco(s) movido(s), {kb(copied)}")

    def cmd_memory_status(self, args):
        _, opts = parse_opts(args, flags=("--reserved", "--virtual", "--frames", "--swap", "--all"))
        if "--reserved" in opts:
            self.reserved_map()
            print()
            self.external_diag()
            return
        if "--frames" in opts:
            return self.frames_map()
        if "--swap" in opts:
            return self.swap_map()
        if "--virtual" in opts:
            self.frames_map()
            for p in self.mem.normal():
                print()
                self.cmd_page_table([str(p.pid)])
            return
        self.occupancy()
        if "--all" in opts:
            print()
            self.frames_map()
            print()
            self.swap_map()

    def occupancy(self):
        mem = self.mem
        st = mem.stats
        crit = mem.critical()
        used_r = sum(p.size for p in crit)
        holes = mem.holes()
        occ = [x for x in mem.frames if x]
        useful = sum(pg.used for _, pg in occ)
        slots = sum(1 for s in mem.slot_of if s)
        procs = mem.normal()
        pages = sum(len(p.pages) for p in procs)
        res = sum(len(p.resident()) for p in procs)
        vsize = sum(p.size for p in procs)
        print(self.s(f"[ANÁLISE DE OCUPAÇÃO DA RAM] t = {mem.clock} ms | substituição: {ALG_NAMES[self.alg]}", "1"))
        print(f"RAM física total: {kb(mem.reserved + mem.dynamic)} = Área Reservada {kb(mem.reserved)} (contígua) + "
              f"RAM Dinâmica {kb(mem.dynamic)} ({mem.nframes} molduras x {kb(mem.page)})")
        print()
        print(self.s("--- ÁREA CRÍTICA/RESERVADA (alocação contígua, sem paginação) ---", "1"))
        print(f"Ocupação  : {bar(used_r / mem.reserved)} {kb(used_r)} / {kb(mem.reserved)} ({pct(used_r, mem.reserved)})")
        print(f"Processos : {len(crit)} (inclui o núcleo base) | Livre: {kb(mem.reserved - used_r)} em "
              f"{len(holes)} lacuna(s) | Maior lacuna: {kb(max((h[1] for h in holes), default=0))} | "
              f"Compactações: {mem.compactions}")
        print()
        print(self.s("--- MEMÓRIA VIRTUAL (paginação por demanda) ---", "1"))
        print(f"RAM Dinâmica : {bar(len(occ) / mem.nframes)} {len(occ)}/{mem.nframes} molduras "
              f"({pct(len(occ), mem.nframes)}) | bytes úteis {kb(useful)} de {kb(len(occ) * mem.page)}")
        print(f"Swap         : {bar(slots / mem.nslots)} {slots}/{mem.nslots} slots ({kb(slots * mem.page)}) em "
              f"{SWAP_PATH} -> {self.storage.array.title}")
        print(f"Espaço virtual: {len(procs)} processo(s), {pages} páginas lógicas ({kb(vsize)}) -> {res} residentes "
              f"na RAM, {pages - res} somente no swap")
        print(f"Referências  : {st['refs']} | Hits: {st['hits']} | Page faults: {st['faults']} "
              f"({pct(st['faults'], st['refs'])}) | Substituições: {st['evictions']} | "
              f"Swap-out: {st['swap_out']} | Swap-in: {st['swap_in']}")
        print()
        print(f"{'PID':>4}  {'PROCESSO':<20} {'DONO':<8} {'TAMANHO':>9}  {'RAM':<26} {'FAULTS':>7}")
        for p in sorted(mem.procs.values(), key=lambda x: x.pid):
            if p.critical:
                ram = f"{kb(p.size)} contíguos"
                faults = "-"
            else:
                r = len(p.resident())
                ram = f"{r}/{len(p.pages)} pág. ({kb(r * mem.page)})"
                faults = str(p.faults)
            print(f"{p.pid:>4}  {p.name:<20} {p.owner:<8} {kb(p.size):>9}  {ram:<26} {faults:>7}")

    def frames_map(self):
        mem = self.mem
        print(self.s(f"--- MAPA DA RAM DINÂMICA ({mem.nframes} molduras de {kb(mem.page)}, a partir de "
                     f"0x{mem.reserved:08X}) ---", "1"))
        hand = self.alg == "segunda_chance"
        print(f"{'MOLD':>4}  {'END. FÍSICO':>11}  {'PID':>4}  {'PROCESSO':<18} {'PÁG':>3}  R  M  {'USO':>5}  "
              f"{'CARGA':>6}  {'ÚLT.':>6}")
        for f, x in enumerate(mem.frames):
            ptr = " <- ponteiro" if hand and f == mem.hand else ""
            if x is None:
                print(f"{f:>4}  0x{mem.frame_addr(f):08X}  {'-':>4}  {'(livre)':<18}{ptr}")
                continue
            p, pg = x
            print(f"{f:>4}  0x{mem.frame_addr(f):08X}  {p.pid:>4}  {p.name:<18} {pg.num:>3}  {pg.ref}  "
                  f"{int(pg.dirty)}  {pg.used * 100 // mem.page:>4}%  {pg.loaded:>4}ms  {pg.last:>4}ms{ptr}")

    def swap_map(self):
        mem = self.mem
        node = self.swap_node()
        print(self.s(f"--- ÁREA DE SWAP: {SWAP_PATH} ({mem.nslots} slots x {kb(mem.page)}) ---", "1"))
        if node is None:
            print("Área de swap ainda não criada (é criada sob demanda).")
            return
        print(f"Arquivo: dono {node.owner}:{node.group} | modo {node.mode:04o} | blocos do disco "
              f"{node.blocks[0] if node.blocks else '-'}..{node.blocks[-1] if node.blocks else '-'}")
        used = [(i, s) for i, s in enumerate(mem.slot_of) if s]
        if not used:
            print("Todos os slots livres.")
        for i, (p, pg) in used:
            lbas, _ = self.swap_range(node, i)
            state = f"também na Moldura {pg.frame}" + (" (RAM mais nova, M=1)" if pg.dirty else "") if pg.present else "somente no swap"
            print(f"Slot {i:>3} (LBA {', '.join(self.storage.bnum(b) for b in lbas)}): PID {p.pid} {p.name} pág {pg.num} | {state}")

    def cmd_mem_config(self, args):
        _, opts = parse_opts(args, valued=("--reserved", "--kernel", "--frames", "--page-size", "--swap-slots",
                                           "--fit", "--tick"), flags=("--force",))
        mem = self.mem
        busy = [p for p in mem.procs.values() if not p.fixed]
        if busy and "--force" not in opts:
            raise FSError(f"há {len(busy)} processo(s) ativos: encerre-os ou use --force")
        try:
            new = Memory(parse_size(opts.get("--reserved", str(mem.reserved))),
                         parse_size(opts.get("--kernel", str(mem.kernel))),
                         int(opts.get("--frames", mem.nframes)),
                         parse_size(opts.get("--page-size", str(mem.page))),
                         int(opts.get("--swap-slots", mem.nslots)),
                         opts.get("--fit", mem.fit), int(opts.get("--tick", mem.tick)), mem.fault_cost)
        except ValueError:
            raise FSError("valores numéricos inválidos")
        old = self.mem
        self.mem = new
        try:
            node = self.make_swap(self.fs)
        except FSError as e:
            self.mem = old
            raise FSError(f"não foi possível dimensionar o swap: {e}")
        self.storage.sync("mem_config: área de swap")
        print(self.s("[CONFIGURAÇÃO DA MEMÓRIA]", "1"))
        print(f"Área Reservada : {kb(new.reserved)} (Núcleo Base do SO: {kb(new.kernel)}) | alocação {new.fit}-fit")
        print(f"RAM Dinâmica   : {new.nframes} molduras x {kb(new.page)} = {kb(new.dynamic)} "
              f"(endereços 0x{new.reserved:08X} a 0x{new.reserved + new.dynamic - 1:08X})")
        print(f"Swap           : {new.nslots} slots x {kb(new.page)} = {kb(node.size)} em {SWAP_PATH} "
              f"({len(node.blocks)} blocos do disco)")
        print(f"Relógio        : {new.tick} ms por referência, +{new.fault_cost} ms por page fault")
        if busy:
            print(self.s(f"Aviso: {len(busy)} processo(s) encerrados pela reconfiguração.", "33"))
        self.log("MEM_CONFIG", f"res={kb(new.reserved)} frames={new.nframes} pag={kb(new.page)} swap={new.nslots}")

    def cmd_demo3(self, args):
        self.no_swap = True
        try:
            return super().cmd_demo3(args)
        finally:
            self.no_swap = False

    def cmd_demo4(self, args):
        root = self.accounts[ROOT]
        self.accounts = {ROOT: root}
        self.groups = {ADMIN: 0}
        self.next_uid = self.next_gid = 1000
        self.stack, self.elevated, self.sudo_ok = [ROOT], False, set()
        self.report_every = 0
        print("\n" + self.s(f"{' DEMONSTRAÇÃO ETAPA 4: GERÊNCIA DE MEMÓRIA ':=^78}", "1;35"))
        return self.run_lines(DEMOS4)


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulador de Gerência de Memória - Etapa 4")
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
    p.add_argument("--reserved", default="4MB")
    p.add_argument("--kernel", default="1MB")
    p.add_argument("--frames", type=int, default=32)
    p.add_argument("--page-size", default="4KB")
    p.add_argument("--swap-slots", type=int, default=32)
    p.add_argument("--mem-fit", choices=["first", "best", "worst"], default="first")
    p.add_argument("--replace", default="lru")
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
        alg = get_replace(a.replace)
        if alg not in LIVE_ALGS:
            p.error("--replace deve ser lru, fifo ou segunda_chance")
        mem = Memory(parse_size(a.reserved), parse_size(a.kernel), a.frames, parse_size(a.page_size),
                     a.swap_slots, a.mem_fit)
        fs = FileSystem(strategy, parse_size(a.block_size), a.blocks, a.fit)
        shell = MemShell(fs, not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ,
                         root_password=a.root_password, mem=mem, replace=alg, media=a.media,
                         alg=get_alg(a.alg), cylinders=a.cylinders, level=RAID_LEVELS[a.raid],
                         ndisks=a.disks)
    except FSError as e:
        p.error(str(e))

    if a.demo:
        shell.execute("demo4")
    elif a.script:
        shell.execute(f"run {shlex.quote(a.script)}")
    else:
        shell.repl()


if __name__ == "__main__":
    main()
