#!/usr/bin/env python3
import argparse
import math
import os
import random
import shlex
import sys

from fs_sim import (DATA, FREE, INODE, STRATEGY_ALIASES, FileSystem, FSError, Shell,
                    fmt_size, parse_opts, parse_size)

ALGORITHMS = {
    "fcfs": "FCFS (First Come, First Served)",
    "sstf": "SSTF (Shortest Seek Time First)",
    "scan": "SCAN (Elevador)",
    "cscan": "C-SCAN (Circular SCAN)",
    "look": "LOOK",
    "clook": "C-LOOK (Circular LOOK)",
}
ALG_ALIASES = {"c-scan": "cscan", "c-look": "clook", "elevador": "scan"}
RAID_LEVELS = {"none": None, "0": 0, "1": 1, "4": 4, "5": 5}


def get_alg(name):
    name = ALG_ALIASES.get(name.lower(), name.lower())
    if name not in ALGORITHMS:
        raise FSError(f"algoritmo inválido: {name} (use {', '.join(ALGORITHMS)})")
    return name


def schedule(alg, head, tracks, cylinders, direction="up"):
    path = [head]
    jumps = set()
    if alg == "fcfs":
        path += tracks
    elif alg == "sstf":
        pending, pos = list(tracks), head
        while pending:
            nxt = min(pending, key=lambda t: (abs(t - pos), t))
            pending.remove(nxt)
            path.append(nxt)
            pos = nxt
    else:
        if direction == "up":
            first = sorted(t for t in tracks if t >= head)
            second = sorted((t for t in tracks if t < head), reverse=True)
            far, near = cylinders - 1, 0
        else:
            first = sorted((t for t in tracks if t <= head), reverse=True)
            second = sorted(t for t in tracks if t > head)
            far, near = 0, cylinders - 1
        path += first
        if second:
            if alg == "scan":
                path.append(far)
                path += second
            elif alg == "look":
                path += second
            elif alg == "cscan":
                path += [far, near]
                jumps.add(len(path) - 1)
                path += second[::-1]
            else:
                jumps.add(len(path))
                path += second[::-1]
    clean, cj = [path[0]], set()
    for i, t in enumerate(path[1:], 1):
        if t != clean[-1]:
            clean.append(t)
            if i in jumps:
                cj.add(len(clean) - 1)
        elif i in jumps:
            cj.add(len(clean) - 1)
    moves = [abs(a - b) for a, b in zip(clean, clean[1:])]
    return clean, moves, cj


def print_schedule(alg, head, tracks, path, moves, jumps):
    print(f"[E/S] Requisições de leitura/escrita pendentes nas trilhas: [{', '.join(map(str, tracks))}]")
    print(f"Posição atual da cabeça de leitura: Trilha {head}")
    print()
    print(f"--- ESCALONAMENTO DE DISCO: {ALGORITHMS[alg]} ---")
    print("Ordem de Atendimento : " + " -> ".join(map(str, path)))
    if not moves:
        print("Total de Movimento    : 0 trilhas")
        return
    print("Deslocamento da Cabeça: " + " + ".join(f"|{a}-{b}|" for a, b in zip(path, path[1:])))
    print(f"Total de Movimento    : {' + '.join(map(str, moves))} = {sum(moves)} trilhas")
    for j in sorted(jumps):
        print(f"Retorno circular      : {path[j - 1]} -> {path[j]} ({moves[j - 1]} trilhas, incluído no total)")


class HDD:
    kind = "HDD"

    def __init__(self, name, capacity, cylinders=200, alg="sstf"):
        self.name = name
        self.capacity = capacity
        self.cylinders = cylinders
        self.alg = alg
        self.head = 0
        self.direction = "up"
        self.pending = []
        self.total_moves = 0
        self.served = 0

    def track(self, off):
        return min(self.cylinders - 1, off * self.cylinders // max(1, self.capacity))

    def preload(self, offsets):
        pass

    def submit(self, ops):
        for op, off, label in ops:
            if op != "T":
                self.pending.append((self.track(off), op, off, label))

    def add_external(self, tracks):
        for t in tracks:
            if not 0 <= t < self.cylinders:
                raise FSError(f"trilha {t} fora do disco (0..{self.cylinders - 1})")
            self.pending.append((t, "R", None, "outro processo"))

    def dispatch(self, verbose=True, compact=False, fmt=str):
        if not self.pending:
            return
        tracks = [p[0] for p in self.pending]
        path, moves, jumps = schedule(self.alg, self.head, tracks, self.cylinders, self.direction)
        if verbose:
            if compact:
                print(f"{self.name} [HDD/{self.alg.upper()}]: fila {tracks} | "
                      f"{' -> '.join(map(str, path))} | {sum(moves)} trilhas")
            else:
                for t, op, off, label in self.pending:
                    where = f"LBA {fmt(off)}" if off is not None else "externa"
                    print(f"  {op} {where:>8} -> trilha {t:<4} {label}")
                print_schedule(self.alg, self.head, tracks, path, moves, jumps)
        for i in range(1, len(path)):
            if i not in jumps:
                self.direction = "up" if path[i] > path[i - 1] else "down"
        self.head = path[-1]
        self.total_moves += sum(moves)
        self.served += len(tracks)
        self.pending = []

    def status(self):
        return (f"{self.name}: HDD {self.cylinders} trilhas | cabeça na trilha {self.head} "
                f"({'subindo' if self.direction == 'up' else 'descendo'}) | algoritmo {self.alg.upper()} | "
                f"{self.served} requisições atendidas | deslocamento acumulado {self.total_moves} trilhas")


class SSD:
    kind = "SSD"

    def __init__(self, name, capacity, pages_per_block=4, wear_leveling=True, threshold=3):
        self.name = name
        self.capacity = capacity
        self.ppb = pages_per_block
        data_blocks = math.ceil(capacity / pages_per_block)
        self.nblocks = data_blocks + max(2, data_blocks // 4)
        self.state = [["-"] * self.ppb for _ in range(self.nblocks)]
        self.lpn = [[None] * self.ppb for _ in range(self.nblocks)]
        self.erase = [0] * self.nblocks
        self.l2p = {}
        self.active = None
        self.wp = 0
        self.wear_leveling = wear_leveling
        self.threshold = threshold
        self.in_gc = False
        self.host_writes = 0
        self.nand_writes = 0
        self.reads = 0
        self.gc_runs = 0
        self.wl_runs = 0
        self.pending = []
        self.log = []

    def is_free(self, b):
        return all(s == "-" for s in self.state[b])

    def free_blocks(self):
        return [b for b in range(self.nblocks) if b != self.active and self.is_free(b)]

    def pname(self, loc):
        return f"B{loc[0]}:P{loc[1]}"

    def alloc(self):
        while True:
            if self.active is not None and self.wp < self.ppb:
                loc = (self.active, self.wp)
                self.wp += 1
                return loc
            free = self.free_blocks()
            if len(free) <= 1 and not self.in_gc:
                self.gc()
                continue
            if not free:
                raise FSError(f"{self.name}: SSD sem páginas livres")
            if self.wear_leveling:
                self.active = min(free, key=lambda b: (self.erase[b], b))
            else:
                self.active = free[0]
            self.wp = 0

    def program(self, lpn):
        old = self.l2p.get(lpn)
        if old:
            self.state[old[0]][old[1]] = "I"
        loc = self.alloc()
        self.state[loc[0]][loc[1]] = "V"
        self.lpn[loc[0]][loc[1]] = lpn
        self.l2p[lpn] = loc
        self.nand_writes += 1
        return old, loc

    def relocate_and_erase(self, b):
        moved = 0
        for p in range(self.ppb):
            if self.state[b][p] == "V":
                self.program(self.lpn[b][p])
                moved += 1
        self.state[b] = ["-"] * self.ppb
        self.lpn[b] = [None] * self.ppb
        self.erase[b] += 1
        return moved

    def gc(self):
        self.in_gc = True
        cands = [b for b in range(self.nblocks)
                 if b != self.active and "I" in self.state[b]]
        if not cands:
            self.in_gc = False
            raise FSError(f"{self.name}: SSD cheio, nada para coletar")
        victim = max(cands, key=lambda b: (self.state[b].count("I"), -self.erase[b]))
        inv = self.state[victim].count("I")
        moved = self.relocate_and_erase(victim)
        self.gc_runs += 1
        self.log.append(f"  GC: bloco B{victim} ({inv} página(s) inválida(s)) -> {moved} válida(s) movida(s), "
                        f"bloco apagado (apagamentos = {self.erase[victim]})")
        if self.wear_leveling:
            self.static_wl()
        self.in_gc = False

    def static_wl(self):
        used = [b for b in range(self.nblocks) if b != self.active and not self.is_free(b)]
        if not used:
            return
        cold = min(used, key=lambda b: (self.erase[b], b))
        if max(self.erase) - self.erase[cold] < self.threshold:
            return
        moved = self.relocate_and_erase(cold)
        self.wl_runs += 1
        self.log.append(f"  WEAR LEVELING estático: dados frios do bloco B{cold} (apagamentos = "
                        f"{self.erase[cold] - 1}) movidos ({moved} pág.) para liberar o bloco pouco gasto")

    def preload(self, offsets):
        for off in offsets:
            self.program(off)
        self.nand_writes = 0
        self.log = []

    def submit(self, ops):
        self.pending.extend(ops)

    def dispatch(self, verbose=True, compact=False, fmt=str):
        if not self.pending:
            return
        lines, counts = [], {"R": 0, "W": 0, "T": 0}
        for op, off, label in self.pending:
            counts[op] += 1
            if op == "R":
                self.reads += 1
                loc = self.l2p.get(off)
                where = self.pname(loc) if loc else "não mapeada"
                lines.append(f"  R LBA {fmt(off)} <- {where:<8} {label}")
            elif op == "W":
                self.host_writes += 1
                old, loc = self.program(off)
                extra = f" (antiga {self.pname(old)} invalidada)" if old else ""
                lines.append(f"  W LBA {fmt(off)} -> {self.pname(loc):<8} {label}{extra}")
                lines.extend(self.log)
                self.log = []
            else:
                old = self.l2p.pop(off, None)
                if old:
                    self.state[old[0]][old[1]] = "I"
                    lines.append(f"  TRIM LBA {fmt(off)}: página {self.pname(old)} marcada como inválida")
        if verbose:
            if compact:
                print(f"{self.name} [SSD]: {counts['W']} escrita(s), {counts['R']} leitura(s), "
                      f"{counts['T']} trim | apagamentos {self.erase}")
            else:
                print(f"[E/S - SSD] {self.name}: acesso direto por página, sem braço mecânico "
                      f"(deslocamento = 0)")
                for line in lines:
                    print(line)
                print(f"  Apagamentos por bloco: {self.erase} | WAF = {self.waf():.2f}")
        self.pending = []

    def waf(self):
        return self.nand_writes / self.host_writes if self.host_writes else 1.0

    def status(self):
        return (f"{self.name}: SSD {self.nblocks} blocos x {self.ppb} páginas | wear leveling "
                f"{'ATIVO' if self.wear_leveling else 'DESATIVADO'} | escritas host {self.host_writes}, "
                f"NAND {self.nand_writes} (WAF {self.waf():.2f}) | GC {self.gc_runs} | WL {self.wl_runs} | "
                f"apagamentos mín {min(self.erase)} / máx {max(self.erase)}")

    def grid(self):
        rows = []
        for b in range(self.nblocks):
            mark = "*" if b == self.active else " "
            rows.append(f"  B{b:<3}{mark} [{' '.join(self.state[b])}]  apagamentos: {self.erase[b]:<4} "
                        + "#" * self.erase[b])
        return rows


class Array:
    def __init__(self, level, ndisks, nblocks, bs, make_device):
        if level is None:
            ndisks = 1
        elif level in (0, 1) and ndisks < 2:
            raise FSError(f"RAID {level} precisa de pelo menos 2 discos")
        elif level in (4, 5) and ndisks < 3:
            raise FSError(f"RAID {level} precisa de pelo menos 3 discos")
        self.level = level
        self.n = ndisks
        self.bs = bs
        self.nblocks = nblocks
        self.zero = bytes(bs)
        if level == 0:
            self.capacity = math.ceil(nblocks / ndisks)
        elif level in (4, 5):
            self.capacity = math.ceil(nblocks / (ndisks - 1))
        else:
            self.capacity = nblocks
        self.make_device = make_device
        self.disks = [make_device(f"Disco {i + 1}", self.capacity) for i in range(ndisks)]
        self.store = [dict() for _ in range(ndisks)]
        self.failed = set()

    @property
    def title(self):
        if self.level is None:
            return "Disco único (sem RAID)"
        return f"RAID {self.level} ({self.n} Discos Físicos, Blocos de {fmt_size(self.bs)})"

    def dpd(self):
        return self.n - 1

    def parity_disk(self, stripe):
        if self.level == 4:
            return self.n - 1
        if self.level == 5:
            return (stripe + 1) % self.n
        return None

    def data_pos(self, lba):
        if self.level is None or self.level == 1:
            return 0, lba
        if self.level == 0:
            return lba % self.n, lba // self.n
        stripe, idx = divmod(lba, self.dpd())
        pd = self.parity_disk(stripe)
        disks = [d for d in range(self.n) if d != pd]
        return disks[idx], stripe

    def stripe_lbas(self, stripe):
        return [stripe * self.dpd() + i for i in range(self.dpd())]

    @staticmethod
    def xor(*chunks):
        acc = 0
        for c in chunks:
            acc ^= int.from_bytes(c, "big")
        return acc.to_bytes(len(chunks[0]), "big")

    def raw(self, d, off):
        return self.store[d].get(off, self.zero)

    def read_unit(self, d, off, ops, label=""):
        if d not in self.failed:
            ops[d].append(("R", off, label))
            return self.raw(d, off), None
        if self.level == 1:
            alive = [x for x in range(self.n) if x not in self.failed]
            if not alive:
                raise FSError("todos os espelhos falharam: dados perdidos")
            ops[alive[0]].append(("R", off, label))
            return self.raw(alive[0], off), f"espelho (Disco {alive[0] + 1})"
        if self.level in (4, 5):
            others = [x for x in range(self.n) if x != d]
            if any(x in self.failed for x in others):
                raise FSError("mais de um disco com falha no arranjo: dados irrecuperáveis")
            for x in others:
                ops[x].append(("R", off, f"reconstrução de {label}"))
            data = self.xor(*[self.raw(x, off) for x in others])
            return data, "XOR(" + " XOR ".join(f"Disco {x + 1}" for x in others) + ")"
        raise FSError(f"Disco {d + 1} falhou e RAID {self.level if self.level is not None else '-'} "
                      f"não tem redundância: dados perdidos")

    def put(self, d, off, data, ops, label):
        if d in self.failed:
            return False
        self.store[d][off] = data
        ops[d].append(("W", off, label))
        return True

    def new_ops(self):
        return [[] for _ in range(self.n)]

    def write(self, items, labeler, verbose=True):
        ops = self.new_ops()
        out = []
        data = {lba: blob for lba, blob in items}
        if self.level is None or self.level == 0:
            for lba, blob in items:
                d, off = self.data_pos(lba)
                if not self.put(d, off, blob, ops, labeler(lba)):
                    out.append(f"Disco {d + 1}: [Bloco {labeler(lba, True)}] -> FALHOU (disco inoperante)")
                else:
                    out.append(f"Disco {d + 1}: [Bloco {labeler(lba, True)}]")
        elif self.level == 1:
            for lba, blob in items:
                for d in range(self.n):
                    ok = self.put(d, lba, blob, ops, labeler(lba))
                    tag = "" if d == 0 else " (espelho)"
                    out.append(f"Disco {d + 1}: [Bloco {labeler(lba, True)}{tag}]"
                               + ("" if ok else " -> não gravado (disco inoperante)"))
        else:
            stripes = {}
            for lba, _ in items:
                stripes.setdefault(lba // self.dpd(), []).append(lba)
            for stripe in sorted(stripes):
                pd = self.parity_disk(stripe)
                members = self.stripe_lbas(stripe)
                full = all(m in data or m >= self.nblocks for m in members)
                old_par = None
                if not full:
                    old_par, _ = self.read_unit(pd, stripe, ops, "paridade antiga") \
                        if pd not in self.failed else (None, None)
                units = []
                out.append(f"Faixa {stripe:02d}" + ("" if full else " (leitura-modificação-escrita)") + ":")
                for m in members:
                    d, off = self.data_pos(m)
                    if m in data:
                        if not full and old_par is not None:
                            old, _ = self.read_unit(d, off, ops, f"{labeler(m)} (antigo)")
                            old_par = self.xor(old_par, old, data[m])
                        ok = self.put(d, off, data[m], ops, labeler(m))
                        units.append(data[m])
                        out.append(f"  Disco {d + 1}: [Bloco {labeler(m, True)}]"
                                   + ("" if ok else " -> disco inoperante (fica só na paridade)"))
                    elif m < self.nblocks:
                        cur = self.raw(d, off) if d not in self.failed else None
                        if cur is None:
                            cur, _ = self.read_unit(d, off, ops, labeler(m))
                        units.append(cur)
                        out.append(f"  Disco {d + 1}: [Bloco {labeler(m, True)} (inalterado)]")
                    else:
                        units.append(self.zero)
                par = old_par if (not full and old_par is not None) else self.xor(*units)
                names = ", ".join(f"Bloco {labeler(m, True).split(':')[0]}" for m in members if m < self.nblocks)
                ok = self.put(pd, stripe, par, ops, f"paridade da faixa {stripe:02d}")
                out.append(f"  Disco {pd + 1}: [PARIDADE : XOR({names})]"
                           + ("" if ok else " -> disco de paridade inoperante"))
        if verbose and self.level is not None:
            print(f"Arranjo Ativo: {self.title}")
            print()
            print("[E/S - DISTRIBUIÇÃO EM DISCO]")
            for line in out:
                print(line)
        return ops

    def read(self, lbas, labeler):
        ops = self.new_ops()
        result, notes = {}, []
        for lba in lbas:
            d, off = self.data_pos(lba)
            if self.level == 1:
                alive = [x for x in range(self.n) if x not in self.failed]
                if alive:
                    d = alive[lba % len(alive)]
            blob, how = self.read_unit(d, off, ops, labeler(lba))
            result[lba] = blob
            if how:
                notes.append(f"* Disco {d + 1} inoperante: Bloco {labeler(lba, True).split(':')[0]} "
                             f"reconstruído via {how}")
        return result, ops, notes

    def rebuild(self, d):
        ops = self.new_ops()
        self.failed.discard(d)
        self.disks[d] = self.make_device(f"Disco {d + 1}", self.capacity)
        self.store[d] = {}
        self.failed.add(d)
        offsets = set()
        for x in range(self.n):
            if x != d:
                offsets |= set(self.store[x])
        restored = 0
        for off in sorted(offsets):
            blob, _ = self.read_unit(d, off, ops)
            self.store[d][off] = blob
            restored += 1
        self.failed.discard(d)
        self.disks[d].preload(sorted(self.store[d]))
        return restored, ops


class Storage:
    def __init__(self, fs, media="hdd", alg="sstf", cylinders=200, level=None, ndisks=3,
                 pages=4, wear=True):
        self.media = media
        self.alg = alg
        self.cylinders = cylinders
        self.level = level
        self.ndisks = ndisks
        self.pages = pages
        self.wear = wear
        self.hold = False
        self.fs = None
        self.attach(fs)

    def make_device(self, name, capacity):
        if self.media == "ssd":
            return SSD(name, capacity, self.pages, self.wear)
        return HDD(name, capacity, self.cylinders, self.alg)

    def attach(self, fs):
        self.fs = fs
        self.array = Array(self.level, self.ndisks, fs.nblocks, fs.bs, self.make_device)
        self.image = self.desired()
        items = [(lba, blob) for lba, blob in sorted(self.image.items())]
        self.array.write(items, self.label, verbose=False)
        for i, dev in enumerate(self.array.disks):
            dev.preload(sorted(self.array.store[i]))

    def uid(self, node):
        if not hasattr(node, "io_uid"):
            node.io_uid = random.getrandbits(32)
        return node.io_uid

    def file_bytes(self, node):
        text = (node.content or "").encode("utf-8")
        rest = node.size - len(text)
        if rest > 0:
            seed = f"<{node.name}:{self.uid(node):08x}>".encode()
            text += (seed * (rest // len(seed) + 1))[:rest]
        return text[:node.size]

    def pad(self, blob):
        return blob.ljust(self.fs.bs, b"\0")[:self.fs.bs]

    def meta_bytes(self, node):
        if node.is_dir:
            body = f"INODE|D|{node.path}|{sorted(node.children)}"
        else:
            body = f"INODE|F|{node.path}|{node.size}|{node.blocks}"
        return self.pad(body.encode("utf-8"))

    def super_bytes(self):
        fs = self.fs
        entries = [(n.path, n.size, n.blocks) for n in fs.all_nodes()]
        return self.pad(f"SUPER|{fs.strategy}|{entries}|{fs.next}".encode("utf-8"))

    def desired(self):
        fs = self.fs
        img, cache = {}, {}
        for b in range(fs.nblocks):
            kind, node = fs.kind[b], fs.owner[b]
            if kind == FREE:
                continue
            if kind == DATA:
                if id(node) not in cache:
                    cache[id(node)] = self.file_bytes(node)
                i = node.blocks.index(b)
                img[b] = self.pad(cache[id(node)][i * fs.bs:(i + 1) * fs.bs])
            elif kind == INODE:
                img[b] = self.meta_bytes(node)
            else:
                img[b] = self.super_bytes()
        return img

    def label(self, lba, numbered=False):
        fs = self.fs
        kind, node = fs.kind[lba], fs.owner[lba]
        if kind == DATA:
            i = node.blocks.index(lba)
            used = fs.used[lba]
            text = f"{node.name} - Parte {i + 1} ({fmt_size(used)})"
        elif kind == INODE:
            text = f"i-node de {node.path}"
        elif kind == FREE:
            text = "livre"
        else:
            text = "superbloco / diretório raiz / tabela"
        return f"{self.bnum(lba)}: {text}" if numbered else text

    def bnum(self, b):
        return f"{b:0{max(2, len(str(self.fs.nblocks - 1)))}d}"

    def meta_lba(self, node):
        return node.inode if node.inode is not None else 0

    def sync(self, title, forced=(), verbose=True):
        new = self.desired()
        order = []
        for node in forced:
            if node.parent is not None or node is self.fs.root:
                order += [b for b in node.blocks if b in new]
        for b in sorted(new):
            if new[b] != self.image.get(b) and b not in order:
                order.append(b)
        trims = [b for b in self.image if b not in new]
        self.image = new
        if not trims or self.media != "ssd" or self.array.level not in (None, 0, 1):
            trims = []
        if not order and not trims:
            return
        if verbose and order:
            reqs = ", ".join(f"W {self.bnum(b)}" for b in order)
            print(f"[E/S] '{title}' gerou {len(order)} requisição(ões) de escrita no disco lógico: {reqs}")
        ops = self.array.write([(b, new[b]) for b in order], self.label, verbose)
        if trims:
            for b in trims:
                if self.array.level == 1:
                    for d in range(self.array.n):
                        ops[d].append(("T", b, "bloco liberado"))
                else:
                    d, off = self.array.data_pos(b)
                    ops[d].append(("T", off, "bloco liberado"))
        self.deliver(ops, verbose)

    def read(self, node, verbose=True):
        lbas = [self.meta_lba(node)] + list(node.blocks)
        if verbose:
            print(f"[E/S] leitura de '{node.path}' gerou {len(lbas)} requisição(ões): "
                  + ", ".join(f"R {self.bnum(b)}" for b in lbas))
        data, ops, notes = self.array.read(lbas, self.label)
        for n in notes:
            print(n)
        self.deliver(ops, verbose)
        return data

    def deliver(self, ops, verbose=True):
        for i, dev in enumerate(self.array.disks):
            if i not in self.array.failed and ops[i]:
                dev.submit(ops[i])
        if not self.hold:
            self.flush(verbose)

    def flush(self, verbose=True):
        compact = len(self.array.disks) > 1
        if compact and verbose and any(d.pending for d in self.array.disks):
            print()
            print("[E/S - ATENDIMENTO NOS DISCOS FÍSICOS]")
        for i, dev in enumerate(self.array.disks):
            if i not in self.array.failed:
                dev.dispatch(verbose, compact, self.bnum)
            else:
                dev.pending = []


HELP2 = """
ETAPA 2 - E/S, ESCALONAMENTO, SSD E RAID
  write_file <arq> [texto] [--size 8KB]  cria/sobrescreve o arquivo e gera E/S
  read_file <arq>                  lê o arquivo gerando E/S (cat também gera)
  disk [hdd|ssd] [--cylinders 200] [--pages 4]   tipo de disco do arranjo
  sched [fcfs|sstf|scan|cscan|look|clook]        algoritmo do braço
  sched <alg> <trilhas...> --head 53 [--dir up|down]   simula uma fila avulsa
  compare [trilhas...] [--head 53] [--dir up|down]     compara os algoritmos
  head <trilha> [--dir up|down] [--disk N]       posiciona a cabeça
  pending <trilhas...> [--disk N]  requisições pendentes de outros processos
  io_load <n> [--seed S] [--disk N]  gera n requisições aleatórias pendentes
  queue hold|auto | flush          acumula requisições / atende a fila
  io_status                        estado dos discos
  wear on|off                      liga/desliga wear leveling (SSD)
  ssd_status [--disk N]            mapa de páginas e apagamentos do SSD
  ssd_stress <arq> <n>             regrava o arquivo n vezes (desgaste)
  raid none|0|1|4|5 [--disks 3]    define o arranjo
  raid_status                      distribuição dos blocos nos discos
  raid_fail <disco>                força a falha de um disco
  raid_test <arq> [disco]          falha um disco e reconstrói os blocos do arquivo
  raid_replace <disco>             troca o disco e reconstrói (rebuild)
  demo2 [sched|ssd|raid]           demonstrações da etapa 2
"""

DEMOS2 = {
    "sched": [
        "# Exemplo 2.1 - fila do braço de disco",
        "sched sstf 98 183 37 122 14 --head 53",
        "compare 98 183 37 122 14 --head 53",
        "# Integração: operações do sistema de arquivos viram requisições de disco",
        "raid none",
        "disk hdd --cylinders 200",
        "format --strategy indexada --block-size 4KB --blocks 64",
        "mkdir -p /sistema/logs",
        "create /sistema/logs/app.log --size 10KB",
        "create /sistema/tmp.bin --size 40KB",
        "create /sistema/outro.txt --size 20KB",
        "rm /sistema/tmp.bin",
        "head 53",
        "pending 98 183 37 122",
        "sched sstf",
        "write_file /sistema/logs/app.log \"Novo Registro\"",
        "pending 98 183 37 122",
        "sched cscan",
        "read_file /sistema/outro.txt",
        "io_status",
    ],
    "ssd": [
        "# SSD: escrita fora do lugar, FTL, coleta de lixo e wear leveling",
        "raid none",
        "disk ssd --pages 4",
        "format --strategy indexada --block-size 4KB --blocks 16",
        "wear off",
        "create /frio.dat --size 16KB",
        "create /quente.log --content \"v0\"",
        "write_file /quente.log \"v1\"",
        "ssd_stress /quente.log 100",
        "ssd_status",
        "wear on",
        "format --strategy indexada --block-size 4KB --blocks 16",
        "create /frio.dat --size 16KB",
        "create /quente.log --content \"v0\"",
        "ssd_stress /quente.log 100",
        "ssd_status",
    ],
    "raid": [
        "# Exemplo 2.2 - gravação sob RAID 5",
        "disk hdd",
        "raid 5 --disks 3",
        "format --strategy indexada --block-size 4KB --blocks 16",
        "write_file /planilha.csv --size 8KB",
        "raid_status",
        "raid_test /planilha.csv 2",
        "read_file /planilha.csv",
        "raid_replace 2",
        "raid 1 --disks 2",
        "write_file /espelho.txt \"conteudo espelhado\"",
        "raid_test /espelho.txt 1",
        "raid 0 --disks 2",
        "write_file /rapido.bin --size 16KB",
        "raid_test /rapido.bin 2",
        "raid 4 --disks 4",
        "write_file /dados.bin --size 12KB",
        "raid_test /dados.bin 1",
    ],
}


class IOShell(Shell):
    storage_cls = Storage

    def __init__(self, fs, color=True, **kw):
        super().__init__(fs, color)
        self.storage = self.storage_cls(fs, **kw)
        self.forced = []
        self.commands.update({
            "write_file": self.cmd_write_file, "read_file": self.cmd_cat,
            "disk": self.cmd_disk, "sched": self.cmd_sched, "compare": self.cmd_compare,
            "head": self.cmd_head, "pending": self.cmd_pending, "io_load": self.cmd_io_load,
            "queue": self.cmd_queue, "flush": self.cmd_flush, "io_status": self.cmd_io_status,
            "wear": self.cmd_wear, "ssd_status": self.cmd_ssd_status, "ssd_stress": self.cmd_ssd_stress,
            "raid": self.cmd_raid, "raid_status": self.cmd_raid_status, "raid_fail": self.cmd_raid_fail,
            "raid_test": self.cmd_raid_test, "raid_replace": self.cmd_raid_replace, "demo2": self.cmd_demo2,
        })

    def execute(self, line, echo=False):
        result = super().execute(line, echo)
        try:
            self.storage.sync(line.strip(), self.forced)
        except FSError as e:
            print(self.s(f"Erro de E/S: {e}", "31"))
        self.forced = []
        return result

    def banner(self):
        super().banner()
        st = self.storage
        print(f"Armazenamento: {st.array.title} | {st.media.upper()}"
              + (f" | braço {st.alg.upper()}" if st.media == "hdd" else "") + "\n")

    def cmd_help(self, args):
        super().cmd_help(args)
        print(HELP2)

    def cmd_format(self, args):
        super().cmd_format(args)
        self.storage.attach(self.fs)

    def cmd_create(self, args):
        super().cmd_create(args)
        pos, _ = parse_opts(args, valued=("--size", "--content", "-s", "-c"))
        self.forced += [self.fs.resolve(p) for p in pos]

    def cmd_write(self, args, append=False):
        super().cmd_write(args, append)
        pos, opts = parse_opts(args, flags=("--append", "-a"))
        if not (append or opts):
            self.forced.append(self.fs.resolve(pos[0]))

    def cmd_cat(self, args):
        super().cmd_cat(args)
        self.storage.read(self.fs.read(args[0]))

    def cmd_write_file(self, args):
        pos, opts = parse_opts(args, valued=("--size", "-s"))
        if not pos:
            raise FSError("uso: write_file <arquivo> [texto] [--size 8KB]")
        path, text = pos[0], " ".join(pos[1:]) if len(pos) > 1 else None
        size = parse_size(opts.get("--size", opts.get("-s", "0")))
        try:
            node = self.fs.read(path)
        except FSError:
            node = None
        if node is None:
            node = self.fs.create(path, size, text)
        elif text is not None:
            node = self.fs.write(path, text)
            if size > node.size:
                node = self.fs.resize(path, size)
        else:
            node.content = None
            self.fs.resize(path, size)
            node.io_uid = random.getrandbits(32)
        self.forced.append(node)
        self.ok(f"Arquivo gravado: {node.path} ({fmt_size(node.size)}) -> {self.describe_alloc(node)}")

    def disks_from(self, opts):
        disks = self.storage.array.disks
        if "--disk" not in opts:
            return disks
        try:
            return [disks[int(opts["--disk"]) - 1]]
        except (ValueError, IndexError):
            raise FSError(f"disco inválido (1..{len(disks)})")

    def hdds(self, opts):
        devs = [d for d in self.disks_from(opts) if d.kind == "HDD"]
        if not devs:
            raise FSError("comando disponível apenas para HDD (use 'disk hdd')")
        return devs

    def cmd_disk(self, args):
        pos, opts = parse_opts(args, valued=("--cylinders", "--pages"))
        st = self.storage
        if pos:
            if pos[0].lower() not in ("hdd", "ssd"):
                raise FSError("uso: disk hdd|ssd [--cylinders N] [--pages N]")
            st.media = pos[0].lower()
        try:
            st.cylinders = int(opts.get("--cylinders", st.cylinders))
            st.pages = int(opts.get("--pages", st.pages))
        except ValueError:
            raise FSError("valores devem ser inteiros")
        if pos or opts:
            st.attach(self.fs)
        self.ok(f"Armazenamento: {st.array.title} | " + (
            f"HDD com {st.cylinders} trilhas por disco, braço {st.alg.upper()}" if st.media == "hdd"
            else f"SSD com {st.pages} páginas por bloco de apagamento, wear leveling "
                 f"{'ativo' if st.wear else 'desativado'}"))

    def sched_input(self, pos, opts):
        tracks = []
        for p in pos:
            try:
                tracks.append(int(p.strip(",[]")))
            except ValueError:
                raise FSError(f"trilha inválida: {p}")
        direction = opts.get("--dir", "up")
        if direction not in ("up", "down"):
            raise FSError("--dir deve ser up ou down")
        try:
            head = int(opts.get("--head", 53))
            cyl = int(opts.get("--cylinders", self.storage.cylinders))
        except ValueError:
            raise FSError("--head e --cylinders devem ser inteiros")
        return tracks, head, direction, cyl

    def cmd_sched(self, args):
        pos, opts = parse_opts(args, valued=("--head", "--dir", "--cylinders"))
        st = self.storage
        if not pos:
            print(f"Algoritmo atual: {ALGORITHMS[st.alg]}")
            return
        alg = get_alg(pos[0])
        if len(pos) == 1 and not opts:
            st.alg = alg
            for d in st.array.disks:
                if d.kind == "HDD":
                    d.alg = alg
            self.ok(f"Escalonamento do braço: {ALGORITHMS[alg]}")
            return
        tracks, head, direction, cyl = self.sched_input(pos[1:], opts)
        if not tracks:
            raise FSError("informe as trilhas pendentes")
        path, moves, jumps = schedule(alg, head, tracks, cyl, direction)
        print_schedule(alg, head, tracks, path, moves, jumps)

    def cmd_compare(self, args):
        pos, opts = parse_opts(args, valued=("--head", "--dir", "--cylinders"))
        if pos:
            tracks, head, direction, cyl = self.sched_input(pos, opts)
        else:
            dev = self.hdds({"--disk": opts.get("--disk", "1")})[0]
            tracks = [p[0] for p in dev.pending]
            head, direction, cyl = dev.head, dev.direction, dev.cylinders
            if not tracks:
                raise FSError("fila vazia: informe trilhas ou use 'queue hold' antes")
        print(f"Fila: {tracks} | cabeça na trilha {head} | sentido {direction} | {cyl} trilhas")
        print(f"{'Algoritmo':<34}{'Ordem de atendimento':<52}{'Total':>7}")
        results = []
        for alg in ALGORITHMS:
            path, moves, _ = schedule(alg, head, tracks, cyl, direction)
            results.append((sum(moves), alg))
            order = " -> ".join(map(str, path))
            if len(order) > 50:
                order = order[:47] + "..."
            print(f"{ALGORITHMS[alg]:<34}{order:<52}{sum(moves):>7}")
        best = min(results, key=lambda r: r[0])
        print(f"Menor deslocamento: {ALGORITHMS[best[1]]} ({best[0]} trilhas)")

    def cmd_head(self, args):
        pos, opts = parse_opts(args, valued=("--dir", "--disk"))
        if len(pos) != 1:
            raise FSError("uso: head <trilha> [--dir up|down] [--disk N]")
        for dev in self.hdds(opts):
            t = int(pos[0])
            if not 0 <= t < dev.cylinders:
                raise FSError(f"trilha fora do disco (0..{dev.cylinders - 1})")
            dev.head = t
            dev.direction = opts.get("--dir", dev.direction)
        self.ok(f"Cabeça posicionada na trilha {pos[0]}")

    def cmd_pending(self, args):
        pos, opts = parse_opts(args, valued=("--disk",))
        tracks, _, _, _ = self.sched_input(pos, {})
        for dev in self.hdds({"--disk": opts.get("--disk", "1")}):
            dev.add_external(tracks)
            print(f"{dev.name}: requisições pendentes de outros processos nas trilhas {tracks}")

    def cmd_io_load(self, args):
        pos, opts = parse_opts(args, valued=("--seed", "--disk"))
        if len(pos) != 1:
            raise FSError("uso: io_load <n> [--seed S] [--disk N]")
        rng = random.Random(opts.get("--seed"))
        for dev in self.hdds({"--disk": opts.get("--disk", "1")}):
            tracks = [rng.randrange(dev.cylinders) for _ in range(int(pos[0]))]
            dev.add_external(tracks)
            print(f"{dev.name}: {len(tracks)} requisições pendentes geradas: {tracks}")

    def cmd_queue(self, args):
        if not args or args[0] not in ("hold", "auto"):
            raise FSError("uso: queue hold|auto")
        self.storage.hold = args[0] == "hold"
        if not self.storage.hold:
            self.storage.flush()
        self.ok("Requisições serão acumuladas até 'flush'" if self.storage.hold
                else "Requisições atendidas a cada operação")

    def cmd_flush(self, args):
        if not any(d.pending for d in self.storage.array.disks):
            print("Fila vazia.")
            return
        self.storage.flush()

    def cmd_io_status(self, args):
        st = self.storage
        print(f"Arranjo: {st.array.title}")
        for i, dev in enumerate(st.array.disks):
            flag = " [FALHOU]" if i in st.array.failed else ""
            print(dev.status() + flag + (f" | {len(dev.pending)} pendente(s)" if dev.pending else ""))

    def cmd_wear(self, args):
        if not args or args[0] not in ("on", "off"):
            raise FSError("uso: wear on|off")
        self.storage.wear = args[0] == "on"
        for d in self.storage.array.disks:
            if d.kind == "SSD":
                d.wear_leveling = self.storage.wear
        self.ok(f"Wear leveling {'ativado' if self.storage.wear else 'desativado'}")

    def ssds(self, opts):
        devs = [d for d in self.disks_from(opts) if d.kind == "SSD"]
        if not devs:
            raise FSError("comando disponível apenas para SSD (use 'disk ssd')")
        return devs

    def cmd_ssd_status(self, args):
        _, opts = parse_opts(args, valued=("--disk",))
        for dev in self.ssds(opts):
            print(dev.status())
            print("  legenda: V = válida, I = inválida, - = livre, * = bloco ativo")
            for row in dev.grid():
                print(row)
            avg = sum(dev.erase) / len(dev.erase)
            print(f"  média de apagamentos {avg:.2f} | diferença máx-mín {max(dev.erase) - min(dev.erase)}")

    def cmd_ssd_stress(self, args):
        if len(args) != 2:
            raise FSError("uso: ssd_stress <arquivo> <n>")
        devs = self.ssds({})
        node = self.fs.read(args[0])
        n = int(args[1])
        for i in range(n):
            if node.content is not None:
                self.fs.write(node.path, f"versão {i + 1}")
            self.storage.sync("ssd_stress", [node], verbose=False)
        print(f"'{node.path}' regravado {n} vezes.")
        for dev in devs:
            print(dev.status())

    def cmd_raid(self, args):
        pos, opts = parse_opts(args, valued=("--disks", "-d"))
        st = self.storage
        if not pos:
            print(st.array.title)
            return
        if pos[0].lower() not in RAID_LEVELS:
            raise FSError("uso: raid none|0|1|4|5 [--disks N]")
        level = RAID_LEVELS[pos[0].lower()]
        try:
            n = int(opts.get("--disks", opts.get("-d", st.ndisks)))
        except ValueError:
            raise FSError("--disks deve ser inteiro")
        if level in (4, 5) and n < 3:
            n = 3
        if level in (0, 1) and n < 2:
            n = 2
        old = (st.level, st.ndisks)
        st.level, st.ndisks = level, n
        try:
            st.attach(self.fs)
        except FSError:
            st.level, st.ndisks = old
            raise
        self.ok(f"Arranjo ativo: {st.array.title}")

    def cmd_raid_status(self, args):
        arr = self.storage.array
        print(f"Arranjo Ativo: {arr.title}")
        rows = max((max(s) + 1 if s else 0) for s in arr.store) if arr.store else 0
        rows = max(rows, 1)
        width = 30
        print("Offset | " + " | ".join(
            f"{('Disco ' + str(i + 1) + (' [FALHOU]' if i in arr.failed else '')):<{width}}"
            for i in range(arr.n)))
        for off in range(min(rows, arr.capacity)):
            cells = []
            for d in range(arr.n):
                cells.append(f"{self.cell(arr, d, off)[:width]:<{width}}")
            print(f"{off:>6} | " + " | ".join(cells))

    def cell(self, arr, d, off):
        st = self.storage
        if arr.level in (4, 5) and arr.parity_disk(off) == d:
            members = [m for m in arr.stripe_lbas(off) if m < arr.nblocks]
            return "P = XOR(" + ",".join(st.bnum(m) for m in members) + ")"
        for lba in range(arr.nblocks):
            pd, poff = arr.data_pos(lba)
            if poff == off and (pd == d or arr.level == 1):
                return f"{st.bnum(lba)} {st.label(lba)}"
        return "-"

    def parse_disk(self, text):
        try:
            d = int(text) - 1
        except ValueError:
            raise FSError("número de disco inválido")
        if not 0 <= d < self.storage.array.n:
            raise FSError(f"disco inválido (1..{self.storage.array.n})")
        return d

    def cmd_raid_fail(self, args):
        if len(args) != 1:
            raise FSError("uso: raid_fail <disco>")
        d = self.parse_disk(args[0])
        self.storage.array.failed.add(d)
        print(self.s(f"* Falha forçada no Disco {d + 1}!", "31;1"))

    def cmd_raid_test(self, args):
        if not args:
            raise FSError("uso: raid_test <arquivo> [disco]")
        st, arr = self.storage, self.storage.array
        node = self.fs.read(args[0])
        lbas = list(node.blocks)
        if not lbas:
            raise FSError("arquivo sem blocos de dados")
        d = self.parse_disk(args[1]) if len(args) > 1 else arr.data_pos(lbas[0])[0]
        print()
        print("[TESTE DE FALHA SIMULADO]")
        arr.failed.add(d)
        print(self.s(f"* Falha forçada no Disco {d + 1}!", "31;1"))
        hit = [b for b in lbas if arr.data_pos(b)[0] == d or arr.level == 1]
        if not hit:
            print(f"* Nenhum bloco de dados de {node.name} estava no Disco {d + 1} "
                  f"(apenas paridade/outros arquivos); leitura segue normal.")
        for b in hit:
            dd, off = arr.data_pos(b)
            if arr.level == 1:
                dd = d
            try:
                blob, how = arr.read_unit(dd, off, arr.new_ops(), st.label(b))
            except FSError as e:
                print(self.s(f"* Bloco {st.bnum(b)} perdido: {e} [FALHA]", "31"))
                continue
            res = self.s("[OK]", "32;1") if blob == st.image.get(b) else self.s("[ERRO]", "31;1")
            if arr.level in (4, 5):
                how = "(" + how[4:-1] + ")"
                print(f"* Recuperando Bloco {st.bnum(b)} via operação XOR: {how} -> Reconstrução {res}")
            else:
                print(f"* Recuperando Bloco {st.bnum(b)} via cópia do {how} -> Reconstrução {res}")
        print(f"Disco {d + 1} permanece inoperante (modo degradado). Use 'raid_replace {d + 1}' para reconstruir.")

    def cmd_raid_replace(self, args):
        if len(args) != 1:
            raise FSError("uso: raid_replace <disco>")
        arr = self.storage.array
        d = self.parse_disk(args[0])
        print(f"Substituindo Disco {d + 1} por um disco novo e reconstruindo...")
        restored, ops = arr.rebuild(d)
        good = sum(1 for off, blob in arr.store[d].items() if blob == self.expected(d, off))
        self.storage.deliver(ops, verbose=False)
        print(f"Rebuild concluído: {restored} unidade(s) restaurada(s) no Disco {d + 1}, "
              f"{good}/{restored} conferida(s) " + self.s("[OK]" if good == restored else "[ERRO]", "32;1"))

    def expected(self, d, off):
        st, arr = self.storage, self.storage.array
        if arr.level in (4, 5) and arr.parity_disk(off) == d:
            units = []
            for m in arr.stripe_lbas(off):
                units.append(st.image.get(m, arr.zero) if m < arr.nblocks else arr.zero)
            return arr.xor(*units)
        for lba in range(arr.nblocks):
            pd, poff = arr.data_pos(lba)
            if poff == off and (pd == d or arr.level == 1):
                return st.image.get(lba, arr.raw(d, off))
        return arr.raw(d, off)

    def cmd_demo2(self, args):
        names = args or list(DEMOS2)
        for name in names:
            if name not in DEMOS2:
                raise FSError(f"demo desconhecida: {name} (use {', '.join(DEMOS2)})")
            title = f" DEMONSTRAÇÃO ETAPA 2: {name.upper()} "
            print("\n" + self.s(f"{title:=^78}", "1;35"))
            if not self.run_lines(DEMOS2[name]):
                return False


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulador de E/S, escalonamento de disco, SSD e RAID - Etapa 2")
    p.add_argument("script", nargs="?")
    p.add_argument("-s", "--strategy", default="indexada")
    p.add_argument("-b", "--block-size", default="4KB")
    p.add_argument("-n", "--blocks", type=int, default=32)
    p.add_argument("--fit", choices=["first", "best", "worst"], default="first")
    p.add_argument("--media", choices=["hdd", "ssd"], default="hdd")
    p.add_argument("--alg", default="sstf")
    p.add_argument("--cylinders", type=int, default=200)
    p.add_argument("--raid", choices=list(RAID_LEVELS), default="none")
    p.add_argument("--disks", type=int, default=3)
    p.add_argument("--demo", nargs="?", const="all")
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
        fs = FileSystem(strategy, parse_size(a.block_size), a.blocks, a.fit)
        shell = IOShell(fs, not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ,
                        media=a.media, alg=get_alg(a.alg), cylinders=a.cylinders,
                        level=RAID_LEVELS[a.raid], ndisks=a.disks)
    except FSError as e:
        p.error(str(e))

    if a.demo:
        shell.execute("demo2" if a.demo == "all" else f"demo2 {a.demo}")
    elif a.script:
        shell.execute(f"run {shlex.quote(a.script)}")
    else:
        shell.repl()


if __name__ == "__main__":
    main()
