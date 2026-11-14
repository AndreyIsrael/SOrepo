#!/usr/bin/env python3

import argparse
import math
import os
import shlex
import string
import sys
from datetime import datetime


FREE, SUPER, INODE, DATA = "LIVRE", "SUPERBLOCO", "INODE", "DADO"
EOF = -1
POINTER_SIZE = 4

STRATEGY_NAMES = {
    "contigua": "Contígua",
    "encadeada": "Encadeada (FAT)",
    "indexada": "Indexada (i-node)",
}
STRATEGY_SHORT = {"contigua": "Contíguo", "encadeada": "Encadeado/FAT", "indexada": "Indexado"}
STRATEGY_ALIASES = {
    "contigua": "contigua", "contígua": "contigua", "contiguous": "contigua", "c": "contigua",
    "encadeada": "encadeada", "linked": "encadeada", "fat": "encadeada", "l": "encadeada", "e": "encadeada",
    "indexada": "indexada", "indexed": "indexada", "inode": "indexada", "i-node": "indexada", "i": "indexada",
}

UNITS = {"B": 1, "K": 1024, "KB": 1024, "KIB": 1024, "M": 1024 ** 2, "MB": 1024 ** 2, "MIB": 1024 ** 2}


class FSError(Exception):
    pass


def parse_size(text):
    t = str(text).strip().upper().replace(" ", "")
    i = 0
    while i < len(t) and (t[i].isdigit() or t[i] in ".,"):
        i += 1
    num, unit = t[:i].replace(",", "."), (t[i:] or "B")
    try:
        value = float(num)
    except ValueError:
        raise FSError(f"tamanho inválido: '{text}'")
    if unit not in UNITS or value < 0:
        raise FSError(f"tamanho inválido: '{text}' (use B, KB ou MB)")
    return int(round(value * UNITS[unit]))


def fmt_size(n):
    if n < 1024:
        return f"{n} B"
    value, unit = (n / 1024, "KB") if n < 1024 ** 2 else (n / 1024 ** 2, "MB")
    return f"{value:.2f}".rstrip("0").rstrip(".") + f" {unit}"


def fmt_pct(x):
    return f"{x:.1f}".rstrip("0").rstrip(".")


class Node:
    def __init__(self, name, is_dir, parent=None):
        self.name = name
        self.is_dir = is_dir
        self.parent = parent
        self.children = {} if is_dir else None
        self.size = 0
        self.content = None
        self.blocks = []
        self.inode = None
        self.ctime = self.mtime = datetime.now()

    @property
    def path(self):
        if self.parent is None:
            return "/"
        p = self.parent.path
        return (p if p.endswith("/") else p + "/") + self.name


class FileSystem:
    def __init__(self, strategy="indexada", block_size=4096, total_blocks=16, fit="first"):
        if strategy not in STRATEGY_NAMES:
            raise FSError(f"estratégia inválida: {strategy}")
        if total_blocks < 2:
            raise FSError("o disco precisa de pelo menos 2 blocos")
        if block_size < 64:
            raise FSError("tamanho mínimo de bloco: 64 B")
        if fit not in ("first", "best", "worst"):
            raise FSError("fit deve ser first, best ou worst")

        self.strategy = strategy
        self.bs = block_size
        self.nblocks = total_blocks
        self.fit = fit

        self.kind = [FREE] * total_blocks
        self.owner = [None] * total_blocks
        self.used = [0] * total_blocks
        self.next = [None] * total_blocks

        self.root = Node("", True)
        self.cwd = self.root
        self.last_failure = None

        if strategy == "indexada":
            self._set(0, self.root, INODE)
            self.root.inode = 0
        else:
            self._set(0, self.root, SUPER)


    def _set(self, b, node, kind, used=0):
        self.kind[b], self.owner[b], self.used[b], self.next[b] = kind, node, used, None

    def _release(self, b):
        self.kind[b], self.owner[b], self.used[b], self.next[b] = FREE, None, 0, None

    def free_list(self):
        return [b for b in range(self.nblocks) if self.kind[b] == FREE]

    def holes(self):
        res, start = [], None
        for b in range(self.nblocks + 1):
            free = b < self.nblocks and self.kind[b] == FREE
            if free and start is None:
                start = b
            elif not free and start is not None:
                res.append((start, b - start))
                start = None
        return res

    def _find_hole(self, n):
        cands = [h for h in self.holes() if h[1] >= n]
        if not cands:
            return None
        if self.fit == "best":
            return min(cands, key=lambda h: (h[1], h[0]))[0]
        if self.fit == "worst":
            return max(cands, key=lambda h: (h[1], -h[0]))[0]
        return cands[0][0]

    def max_blocks_per_file(self):
        if self.strategy == "indexada":
            return self.bs // POINTER_SIZE
        return self.nblocks - 1

    def _alloc_inode(self, node):
        if self.strategy != "indexada":
            return
        free = self.free_list()
        if not free:
            raise FSError("disco cheio: não há bloco livre para o i-node")
        node.inode = free[0]
        self._set(free[0], node, INODE)

    def _relink(self, node):
        if self.strategy != "encadeada":
            return
        for i, b in enumerate(node.blocks):
            self.next[b] = node.blocks[i + 1] if i + 1 < len(node.blocks) else EOF

    def _grow(self, node, add):
        free = self.free_list()
        if add > len(free):
            raise FSError(f"espaço insuficiente: são necessários {add} bloco(s), há {len(free)} livre(s)")

        if self.strategy == "contigua":
            if node.blocks:
                end = node.blocks[-1] + 1
                if end + add <= self.nblocks and all(self.kind[b] == FREE for b in range(end, end + add)):
                    for b in range(end, end + add):
                        self._set(b, node, DATA)
                        node.blocks.append(b)
                    return
            total = len(node.blocks) + add
            saved = [(b, self.used[b]) for b in node.blocks]
            for b, _ in saved:
                self._release(b)
            start = self._find_hole(total)
            if start is None:
                for b, u in saved:
                    self._set(b, node, DATA, u)
                largest = max((h[1] for h in self.holes()), default=0)
                nfree = len(self.free_list())
                self.last_failure = {"path": node.path, "needed": total, "free": nfree, "largest": largest}
                raise FSError(
                    f"FRAGMENTAÇÃO EXTERNA: '{node.path}' precisa de {total} blocos contíguos; "
                    f"há {nfree} blocos livres, mas a maior lacuna contígua tem apenas {largest}. "
                    f"Execute 'compact' para compactar o disco.")
            node.blocks = list(range(start, start + total))
            for b in node.blocks:
                self._set(b, node, DATA)
        else:
            for b in free[:add]:
                self._set(b, node, DATA)
                node.blocks.append(b)
            self._relink(node)

    def _shrink(self, node, keep):
        for b in node.blocks[keep:]:
            self._release(b)
        node.blocks = node.blocks[:keep]
        self._relink(node)

    def _set_size(self, node, size):
        need = math.ceil(size / self.bs)
        if need > self.max_blocks_per_file():
            raise FSError(f"arquivo excede o máximo de {self.max_blocks_per_file()} blocos por arquivo"
                          + (" (capacidade de ponteiros do i-node)" if self.strategy == "indexada" else ""))
        cur = len(node.blocks)
        if need > cur:
            self._grow(node, need - cur)
        elif need < cur:
            self._shrink(node, need)
        node.size = size
        for i, b in enumerate(node.blocks):
            self.used[b] = self.bs if i < need - 1 else size - (need - 1) * self.bs
        self._relink(node)
        node.mtime = datetime.now()


    def _walk(self, start, parts, full):
        node = start
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                node = node.parent or node
                continue
            if not node.is_dir:
                raise FSError(f"'{node.path}' não é um diretório")
            if p not in node.children:
                raise FSError(f"caminho não encontrado: '{full}'")
            node = node.children[p]
        return node

    def resolve(self, path):
        start = self.root if path.startswith("/") else self.cwd
        return self._walk(start, path.split("/"), path)

    def resolve_parent(self, path):
        stripped = path.rstrip("/")
        start = self.root if path.startswith("/") else self.cwd
        parts = stripped.split("/")
        name = parts[-1]
        if name in ("", ".", ".."):
            raise FSError(f"nome inválido: '{path}'")
        parent = self._walk(start, parts[:-1], path)
        if not parent.is_dir:
            raise FSError(f"'{parent.path}' não é um diretório")
        return parent, name

    @staticmethod
    def _is_ancestor(a, b):
        while b is not None:
            if b is a:
                return True
            b = b.parent
        return False

    def all_nodes(self, include_root=False):
        out = [self.root] if include_root else []

        def walk(d):
            for c in sorted(d.children.values(), key=lambda n: n.name):
                out.append(c)
                if c.is_dir:
                    walk(c)
        walk(self.root)
        return out

    def files(self):
        return [n for n in self.all_nodes() if not n.is_dir]


    def _new_node(self, parent, name, is_dir):
        node = Node(name, is_dir, parent)
        if not is_dir:
            self._alloc_inode(node)
        parent.children[name] = node
        parent.mtime = datetime.now()
        return node

    def mkdir(self, path, parents=False):
        if parents:
            node = self.root if path.startswith("/") else self.cwd
            for p in path.split("/"):
                if p in ("", "."):
                    continue
                if p == "..":
                    node = node.parent or node
                elif p in node.children:
                    node = node.children[p]
                    if not node.is_dir:
                        raise FSError(f"'{node.path}' existe e não é um diretório")
                else:
                    node = self._new_node(node, p, True)
            return node
        parent, name = self.resolve_parent(path)
        if name in parent.children:
            raise FSError(f"já existe: '{parent.children[name].path}'")
        return self._new_node(parent, name, True)

    def create(self, path, size=0, content=None):
        parent, name = self.resolve_parent(path)
        if name in parent.children:
            raise FSError(f"já existe: '{parent.children[name].path}'")
        if content is not None:
            size = max(size, len(content.encode("utf-8")))
        node = self._new_node(parent, name, False)
        try:
            self._set_size(node, size)
        except FSError:
            self._delete_node(node)
            raise
        node.content = content
        return node

    def read(self, path):
        node = self.resolve(path)
        if node.is_dir:
            raise FSError(f"'{node.path}' é um diretório (use ls)")
        return node

    def write(self, path, text, append=False):
        node = self.read(path)
        if append:
            base = node.content or ""
            simulated = node.size - len(base.encode("utf-8"))
            new_content = base + text
            new_size = len(new_content.encode("utf-8")) + max(0, simulated)
        else:
            new_content = text
            new_size = len(text.encode("utf-8"))
        self._set_size(node, new_size)
        node.content = new_content
        return node

    def resize(self, path, size):
        node = self.read(path)
        self._set_size(node, size)
        if node.content is not None:
            raw = node.content.encode("utf-8")
            if len(raw) > size:
                node.content = raw[:size].decode("utf-8", errors="ignore")
        return node

    def move(self, src, dst):
        node = self.resolve(src)
        if node is self.root:
            raise FSError("não é possível mover a raiz")
        try:
            target = self.resolve(dst)
        except FSError:
            target = None
        if target is not None and target.is_dir:
            parent, name = target, node.name
        else:
            if target is not None:
                raise FSError(f"destino já existe: '{target.path}'")
            parent, name = self.resolve_parent(dst)
        if node.is_dir and self._is_ancestor(node, parent):
            raise FSError("não é possível mover um diretório para dentro dele mesmo")
        if name in parent.children:
            raise FSError(f"destino já existe: '{parent.children[name].path}'")
        del node.parent.children[node.name]
        node.name, node.parent = name, parent
        parent.children[name] = node
        node.mtime = datetime.now()
        return node

    def _delete_node(self, node):
        if node.is_dir:
            for c in list(node.children.values()):
                self._delete_node(c)
        for b in node.blocks:
            self._release(b)
        node.blocks = []
        if node.inode is not None:
            self._release(node.inode)
            node.inode = None
        if node.parent is not None and node.parent.children.get(node.name) is node:
            del node.parent.children[node.name]

    def remove(self, path, recursive=False, only_dir=False):
        node = self.resolve(path)
        if node is self.root:
            raise FSError("não é possível remover a raiz '/'")
        if only_dir and not node.is_dir:
            raise FSError(f"'{node.path}' não é um diretório (use rm)")
        if node.is_dir and node.children and not recursive:
            raise FSError(f"diretório '{node.path}' não está vazio (use -r)")
        if node.is_dir and not only_dir and not recursive:
            raise FSError(f"'{node.path}' é um diretório (use rmdir ou rm -r)")
        if self._is_ancestor(node, self.cwd):
            self.cwd = node.parent
        freed = self._count_blocks(node)
        self._delete_node(node)
        return node, freed

    def _count_blocks(self, node):
        n = len(node.blocks) + (1 if node.inode is not None else 0)
        if node.is_dir:
            n += sum(self._count_blocks(c) for c in node.children.values())
        return n


    def compact(self):
        seq = []
        for n in self.all_nodes():
            if n.inode is not None:
                seq.append((n, INODE, 0, n.inode))
            for b in n.blocks:
                seq.append((n, DATA, self.used[b], b))
        for b in range(1, self.nblocks):
            self._release(b)
        for n in self.all_nodes():
            n.blocks = []
            if n is not self.root:
                n.inode = None
        moved = 0
        for pos, (n, kind, used, old) in enumerate(seq, start=1):
            self._set(pos, n, kind, used)
            if kind == INODE:
                n.inode = pos
            else:
                n.blocks.append(pos)
            moved += pos != old
        for n in self.files():
            self._relink(n)
        self.last_failure = None
        return moved


    def external_frag(self):
        holes = self.holes()
        free = sum(h[1] for h in holes)
        largest = max((h[1] for h in holes), default=0)
        info = {"holes": holes, "free": free, "largest": largest, "frag_blocks": 0, "frag_set": set()}
        if self.strategy == "contigua" and len(holes) > 1:
            idx = max(range(len(holes)), key=lambda i: (holes[i][1], -i))
            for i, (s, ln) in enumerate(holes):
                if i != idx:
                    info["frag_set"].update(range(s, s + ln))
            info["frag_blocks"] = len(info["frag_set"])
        return info

    @staticmethod
    def runs(blocks):
        if not blocks:
            return 0
        return 1 + sum(1 for a, b in zip(blocks, blocks[1:]) if b != a + 1)

    def compaction_verdict(self):
        scattered = [f for f in self.files() if self.runs(f.blocks) > 1]
        if self.strategy in ("indexada", "encadeada"):
            why = ("Blocos alocados via i-node indexado" if self.strategy == "indexada"
                   else "Alocação encadeada (FAT): qualquer bloco livre pode ser usado")
            extra = (f"; 'compact' é opcional (desempenho): {len(scattered)} arquivo(s) com blocos dispersos"
                     if scattered else "")
            return "NÃO", why + extra
        ef = self.external_frag()
        lf = self.last_failure
        if ef["free"] == 0:
            return "NÃO", "disco cheio — não há espaço livre a reorganizar"
        if lf and ef["largest"] < lf["needed"] <= ef["free"]:
            return "SIM", (f"a alocação de {lf['needed']} blocos para '{lf['path']}' falhou: há {ef['free']} "
                           f"blocos livres, mas a maior lacuna contígua tem {ef['largest']}")
        if len(ef["holes"]) > 1 and ef["frag_blocks"] * 2 >= ef["free"]:
            return "SIM", (f"{ef['frag_blocks']} de {ef['free']} blocos livres estão dispersos em "
                           f"{len(ef['holes'])} lacunas")
        if len(ef["holes"]) > 1:
            return "RECOMENDADA", (f"espaço livre dividido em {len(ef['holes'])} lacunas "
                                   f"(maior = {ef['largest']} blocos)")
        return "NÃO", "todo o espaço livre é contíguo"


class Style:
    PALETTE = [27, 160, 28, 166, 91, 30, 130, 61, 64, 125, 24, 136, 54, 22, 88, 58]

    def __init__(self, enabled):
        self.on = enabled

    def __call__(self, text, codes=""):
        return f"\033[{codes}m{text}\033[0m" if self.on and codes else text


def parse_opts(args, valued=(), flags=()):
    pos, opts, i = [], {}, 0
    while i < len(args):
        a = args[i]
        key = a.split("=", 1)[0]
        if a in flags:
            opts[a] = True
        elif a in valued:
            if i + 1 >= len(args):
                raise FSError(f"a opção {a} requer um valor")
            opts[a] = args[i + 1]
            i += 1
        elif "=" in a and key in valued:
            opts[key] = a.split("=", 1)[1]
        elif a.startswith("-") and len(a) > 1 and not a[1].isdigit():
            raise FSError(f"opção desconhecida: {a}")
        else:
            pos.append(a)
        i += 1
    return pos, opts


HELP = """
COMANDOS DISPONÍVEIS
  Árvore / navegação
    pwd                              mostra o diretório atual
    cd <caminho>                     muda de diretório (aceita /, ., ..)
    ls [caminho]                     lista um diretório
    tree [caminho]                   mostra a árvore hierárquica

  CRUD
    mkdir [-p] <dir>...              cria diretório(s)
    create <arq> [--size 10KB] [--content "texto"]   cria arquivo (alias: touch)
    cat <arq>                        lê o conteúdo (alias: read)
    stat <caminho>                   metadados + blocos físicos do arquivo
    write <arq> <texto> [--append]   sobrescreve/acrescenta conteúdo (atualiza)
    append <arq> <texto>             acrescenta conteúdo
    resize <arq> --size 8KB          altera o tamanho (alias: truncate)
    mv <origem> <destino>            move/renomeia (alias: rename)
    rm [-r] <caminho>                remove arquivo (ou diretório com -r)
    rmdir [-r] <dir>                 remove diretório

  Disco / diagnóstico
    format [--strategy contigua|encadeada|indexada] [--block-size 4KB]
           [--blocks 16] [--fit first|best|worst]     reformata o disco
    fs_status [--details]            estado do disco, mapa e fragmentação
    map                              mapa gráfico dos blocos
    frag                             relatório de fragmentação detalhado
    fat                              tabela FAT (alocação encadeada)
    compact                          compacta/desfragmenta o disco (alias: defrag)

  Outros
    demo [indexada|contigua|encadeada]   executa demonstrações
    run <arquivo>                    executa comandos de um arquivo
    help | clear | exit
"""


class Shell:
    def __init__(self, fs, color=True):
        self.fs = fs
        self.s = Style(color)
        self.commands = {
            "help": self.cmd_help, "?": self.cmd_help,
            "pwd": self.cmd_pwd, "cd": self.cmd_cd, "ls": self.cmd_ls, "tree": self.cmd_tree,
            "mkdir": self.cmd_mkdir, "create": self.cmd_create, "touch": self.cmd_create,
            "cat": self.cmd_cat, "read": self.cmd_cat, "stat": self.cmd_stat, "info": self.cmd_stat,
            "write": self.cmd_write, "append": self.cmd_append,
            "resize": self.cmd_resize, "truncate": self.cmd_resize,
            "mv": self.cmd_mv, "rename": self.cmd_mv,
            "rm": self.cmd_rm, "delete": self.cmd_rm, "rmdir": self.cmd_rmdir,
            "format": self.cmd_format, "fs_status": self.cmd_status, "status": self.cmd_status,
            "df": self.cmd_status, "map": self.cmd_map, "frag": self.cmd_frag, "fat": self.cmd_fat,
            "compact": self.cmd_compact, "defrag": self.cmd_compact,
            "demo": self.cmd_demo, "run": self.cmd_run, "clear": self.cmd_clear,
            "echo": self.cmd_echo, "exit": self.cmd_exit, "quit": self.cmd_exit,
        }


    def ok(self, msg):
        print(self.s(msg, "32"))

    def execute(self, line, echo=False):
        line = line.strip()
        if not line:
            return True
        if line.startswith("#"):
            if echo:
                print(self.s(line, "2"))
            return True
        if echo:
            print(self.s(f"> {line}", "1"))
        try:
            args = shlex.split(line)
        except ValueError as e:
            print(self.s(f"Erro de sintaxe: {e}", "31"))
            return True
        handler = self.commands.get(args[0].lower())
        if handler is None:
            print(self.s(f"Comando desconhecido: '{args[0]}'. Digite 'help'.", "31"))
            return True
        try:
            return handler(args[1:]) is not False
        except FSError as e:
            print(self.s(f"Erro: {e}", "31"))
        return True

    def repl(self):
        try:
            import readline
        except ImportError:
            pass
        self.banner()
        while True:
            try:
                line = input(self.s(f"{self.fs.cwd.path}", "36;1") + "> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not self.execute(line):
                break

    def banner(self):
        fs = self.fs
        print(self.s("Simulador de Sistema de Arquivos — Etapa 1", "1"))
        print(f"Disco: {fs.nblocks} blocos x {fmt_size(fs.bs)} = {fmt_size(fs.nblocks * fs.bs)} | "
              f"Alocação: {STRATEGY_NAMES[fs.strategy]}"
              + (f" ({fs.fit}-fit)" if fs.strategy == "contigua" else ""))
        print("Digite 'help' para ver os comandos ou 'demo' para uma demonstração.\n")

    def run_lines(self, lines):
        for line in lines:
            if not self.execute(line, echo=True):
                return False
        return True


    def bnum(self, b):
        return f"{b:0{max(2, len(str(self.fs.nblocks - 1)))}d}"

    def blist(self, blocks):
        return ", ".join(self.bnum(b) for b in blocks) if blocks else "—"

    def tree_lines(self, node):
        out = ["/" if node is self.fs.root else node.path + "/"]

        def rec(d, prefix):
            kids = sorted(d.children.values(), key=lambda n: (not n.is_dir, n.name))
            for i, k in enumerate(kids):
                last = i == len(kids) - 1
                conn = "└── " if last else "├── "
                if k.is_dir:
                    out.append(f"{prefix}{conn}{k.name}/ [DIR]")
                    rec(k, prefix + ("    " if last else "│   "))
                else:
                    out.append(f"{prefix}{conn}{k.name} ({fmt_size(k.size)}) [ARQ]")
        rec(node, "")
        return out

    def symbols(self):
        pool = string.ascii_uppercase + string.ascii_lowercase + string.digits
        syms, colors, i = {self.fs.root: "/"}, {self.fs.root: 240}, 0
        for n in self.fs.all_nodes():
            if n.blocks or n.inode is not None:
                syms[n] = pool[i] if i < len(pool) else "#"
                colors[n] = Style.PALETTE[i % len(Style.PALETTE)]
                i += 1
        return syms, colors

    def inode_label(self, node):
        if node is self.fs.root:
            return "INODE_RAIZ"
        stem = node.name.rsplit(".", 1)[0] if "." in node.name[1:] else node.name
        return ("INODE_" + stem.upper())[:16]

    def header(self, details=False):
        fs = self.fs
        lines = [f"Tamanho do Bloco de Disco: {fmt_size(fs.bs)} | Total de Blocos: {fs.nblocks} "
                 f"({fmt_size(fs.bs * fs.nblocks)})"]
        if not details:
            used = fs.nblocks - len(fs.free_list())
            lines.append(
                f"Estratégia: {STRATEGY_NAMES[fs.strategy]}"
                + (f" [{fs.fit}-fit]" if fs.strategy == "contigua" else "")
                + f" | Blocos ocupados: {used}/{fs.nblocks} ({fmt_pct(used * 100 / fs.nblocks)}%) | "
                f"Livres: {fs.nblocks - used} ({fmt_size((fs.nblocks - used) * fs.bs)})")
        return lines

    def block_listing(self):
        fs = self.fs
        ef = fs.external_frag()
        rows = []
        b = 0
        while b < fs.nblocks:
            k, n = fs.kind[b], fs.owner[b]
            if k == FREE:
                frag = b in ef["frag_set"]
                e = b
                while e + 1 < fs.nblocks and fs.kind[e + 1] == FREE and ((e + 1) in ef["frag_set"]) == frag:
                    e += 1
                left = f"Bloco {self.bnum(b)}" + (f"..{self.bnum(e)}" if e > b else "")
                rows.append((left, "", "[LIVRE]" + ("  ← fragmento externo (lacuna isolada)" if frag else "")))
                b = e + 1
                continue
            left = f"Bloco {self.bnum(b)}"
            if k == SUPER:
                desc = "Superbloco + diretório raiz '/'" + (" + tabela FAT" if fs.strategy == "encadeada" else "")
                rows.append((left, "[SUPERBLOCO]", desc))
            elif k == INODE:
                if n.is_dir:
                    desc = f"Diretório '{n.path}'"
                else:
                    desc = f"Arquivo '{n.path}'"
                rows.append((left, f"[{self.inode_label(n)}]", desc))
            else:
                idx = n.blocks.index(b) + 1
                desc = f"'{n.path}' (Bloco {idx} - {fs.used[b]} bytes ocupados)"
                if fs.strategy == "encadeada":
                    nxt = fs.next[b]
                    desc += "  → próx: " + ("EOF" if nxt == EOF else self.bnum(nxt))
                rows.append((left, "[DADO]", desc))
            b += 1
        texts = [f"{left} {typ}" if typ else left for left, typ, _ in rows]
        width = max(len(t) for t in texts) + 2
        out = [self.s(f"[MAPA DE ALOCAÇÃO DO DISCO ({STRATEGY_SHORT[fs.strategy]})]", "1")]
        for text, (_, _, desc) in zip(texts, rows):
            out.append(f"{text:<{width}}: {desc}")
        return out

    def graphic_map(self):
        fs, s = self.fs, self.s
        syms, colors = self.symbols()
        ef = fs.external_frag()
        per_row = 16
        width = len(self.bnum(fs.nblocks - 1))
        used = fs.nblocks - ef["free"]
        bar_len = 32
        filled = round(bar_len * used / fs.nblocks)
        out = [s(f"[MAPA GRÁFICO DO DISCO — {STRATEGY_NAMES[fs.strategy]} | "
                 f"{fs.nblocks} blocos x {fmt_size(fs.bs)}]", "1"),
               f"Ocupação [{'█' * filled}{'░' * (bar_len - filled)}] {fmt_pct(used * 100 / fs.nblocks)}%", ""]
        out.append(" " * (width + 3) + "".join(f"{c:<4}"[:4] for c in
                                               (f"+{i:02d}" if i else "+00" for i in range(per_row))))
        for row in range(0, fs.nblocks, per_row):
            cells = []
            for b in range(row, min(row + per_row, fs.nblocks)):
                k, n = fs.kind[b], fs.owner[b]
                if k == FREE:
                    text, code = ("░░", "48;5;52;38;5;210") if b in ef["frag_set"] else ("··", "2")
                elif k == SUPER:
                    text, code = "SB", "48;5;240;97"
                else:
                    sym = syms.get(n, "?")
                    code = f"48;5;{colors.get(n, 240)};97;1"
                    if k == INODE:
                        text = "i" + sym
                    else:
                        text = sym + ("~" if fs.used[b] < fs.bs else " ")
                cells.append(s(f" {text} ", code) if s.on else f"[{text}]")
            out.append(f"{str(row).rjust(width)} | " + "".join(cells))
        out.append("")
        out.append("Legenda: X = bloco de dados | X~ = último bloco parcial (fragmentação interna) | "
                   "iX = i-node | SB = superbloco")
        out.append("         ·· = livre" + (" | ░░ = livre disperso (fragmentação externa)"
                                            if fs.strategy == "contigua" else ""))
        for n in fs.all_nodes():
            if n not in syms:
                continue
            sample = s(f" {syms[n]} ", f"48;5;{colors[n]};97;1") if s.on else f"[{syms[n]}]"
            if n.is_dir:
                out.append(f"  {sample} {n.path}/ (i-node no bloco {self.bnum(n.inode)})")
            else:
                internal = len(n.blocks) * fs.bs - n.size
                info = f"{len(n.blocks)} bloco(s) de dados"
                if n.inode is not None:
                    info += f" + i-node {self.bnum(n.inode)}"
                if internal:
                    info += f", frag. interna {internal} B"
                out.append(f"  {sample} {n.path} — {fmt_size(n.size)}, {info}")
        return out

    def frag_report(self, details=True):
        fs = self.fs
        files = fs.files()
        items = []

        def blocos(n):
            return f"{n} bloco{'s' if n != 1 else ''} de {fmt_size(fs.bs)}"

        total_int = 0
        for f in files:
            alloc = len(f.blocks) * fs.bs
            internal = alloc - f.size
            total_int += internal
            if not details:
                continue
            if items:
                items.append(None)
            items.append((f"Tamanho Real do Arquivo '{f.name}'", f"{f.size} bytes ({fmt_size(f.size)})"))
            items.append(("Espaço Alocado no Disco", f"{alloc} bytes ({blocos(len(f.blocks))})"))
            if internal:
                items.append(("Fragmentação Interna", f"{internal} bytes ({fmt_pct(internal * 100 / fs.bs)}% "
                                                      f"de desperdício no Bloco {self.bnum(f.blocks[-1])})"))
            else:
                items.append(("Fragmentação Interna", "0 bytes"))
        if details and len(files) > 1:
            items.append(None)
        if not details or len(files) > 1:
            items.append(("Fragmentação Interna (total)", f"{total_int} bytes em {len(files)} arquivo(s)"))

        ef = fs.external_frag()
        if fs.strategy == "contigua" and ef["frag_blocks"]:
            items.append(("Fragmentação Externa", f"{ef['frag_blocks'] * fs.bs} bytes "
                                                  f"({ef['frag_blocks']} blocos livres dispersos fora da maior lacuna)"))
            holes = ", ".join(f"[{self.bnum(st)}..{self.bnum(st + ln - 1)}]({ln})" for st, ln in ef["holes"])
            items.append(("Lacunas Livres", holes))
            items.append(("Maior Lacuna Contígua", f"{ef['largest']} bloco(s) = {fmt_size(ef['largest'] * fs.bs)}"))
        else:
            items.append(("Fragmentação Externa", "0 bytes"))
        verdict, why = fs.compaction_verdict()
        color = {"SIM": "31;1", "RECOMENDADA": "33;1", "NÃO": "32;1"}[verdict]
        items.append(("Necessidade de Compactação", f"{self.s(verdict, color)} ({why})"))

        width = max(len(it[0]) for it in items if it)
        out = [self.s("--- RELATÓRIO DE FRAGMENTAÇÃO ---", "1")]
        if not files:
            out.append("(nenhum arquivo no disco)")
        for it in items:
            out.append("" if it is None else f"{it[0]:<{width}}: {it[1]}")
        return out


    def cmd_help(self, args):
        print(HELP)

    def cmd_pwd(self, args):
        print(self.fs.cwd.path)

    def cmd_cd(self, args):
        node = self.fs.resolve(args[0] if args else "/")
        if not node.is_dir:
            raise FSError(f"'{node.path}' não é um diretório")
        self.fs.cwd = node

    def cmd_ls(self, args):
        node = self.fs.resolve(args[0] if args else ".")
        if not node.is_dir:
            print(f"[ARQ]  {node.name}  {fmt_size(node.size)}  blocos: {self.blist(node.blocks)}")
            return
        kids = sorted(node.children.values(), key=lambda n: (not n.is_dir, n.name))
        if not kids:
            print("(vazio)")
        for k in kids:
            if k.is_dir:
                print(f"[DIR]  {self.s(k.name + '/', '34;1')}")
            else:
                print(f"[ARQ]  {k.name:<24} {fmt_size(k.size):>10}   {len(k.blocks)} bloco(s)")

    def cmd_tree(self, args):
        node = self.fs.resolve(args[0] if args else "/")
        if not node.is_dir:
            raise FSError(f"'{node.path}' não é um diretório")
        print(self.s("[ÁRVORE DO SISTEMA DE ARQUIVOS]", "1"))
        print("\n".join(self.tree_lines(node)))

    def cmd_mkdir(self, args):
        pos, opts = parse_opts(args, flags=("-p",))
        if not pos:
            raise FSError("uso: mkdir [-p] <dir>...")
        for p in pos:
            self.fs.mkdir(p, parents="-p" in opts)

    def cmd_create(self, args):
        pos, opts = parse_opts(args, valued=("--size", "--content", "-s", "-c"))
        if not pos:
            raise FSError("uso: create <arquivo> [--size 10KB] [--content \"texto\"]")
        size = parse_size(opts.get("--size", opts.get("-s", "0")))
        content = opts.get("--content", opts.get("-c"))
        for p in pos:
            self.fs.create(p, size, content)

    def describe_alloc(self, node):
        if not node.blocks:
            base = "nenhum bloco de dados"
        else:
            base = f"{len(node.blocks)} bloco(s): [{self.blist(node.blocks)}]"
        if node.inode is not None:
            base = f"i-node {self.bnum(node.inode)}, " + base
        return base

    def cmd_cat(self, args):
        if not args:
            raise FSError("uso: cat <arquivo>")
        node = self.fs.read(args[0])
        if node.content is not None:
            print(node.content)
            extra = node.size - len(node.content.encode("utf-8"))
            if extra > 0:
                print(self.s(f"(+ {extra} bytes de conteúdo simulado)", "2"))
        else:
            print(self.s(f"(conteúdo simulado: {node.size} bytes — arquivo criado com --size)", "2"))

    def cmd_stat(self, args):
        fs = self.fs
        node = fs.resolve(args[0] if args else ".")
        print(f"Caminho      : {node.path}")
        print(f"Tipo         : {'Diretório' if node.is_dir else 'Arquivo'}")
        if node.is_dir:
            print(f"Entradas     : {len(node.children)}")
        else:
            print(f"Tamanho      : {node.size} bytes ({fmt_size(node.size)})")
            print(f"Alocado      : {len(node.blocks) * fs.bs} bytes ({len(node.blocks)} bloco(s))")
            print(f"Frag. interna: {len(node.blocks) * fs.bs - node.size} bytes")
            if fs.strategy == "contigua":
                if node.blocks:
                    print(f"Alocação     : contígua — início = {self.bnum(node.blocks[0])}, "
                          f"comprimento = {len(node.blocks)}")
            elif fs.strategy == "encadeada":
                chain = " → ".join(self.bnum(b) for b in node.blocks) + " → EOF" if node.blocks else "EOF"
                print(f"Cadeia FAT   : {chain}")
            print(f"Blocos       : [{self.blist(node.blocks)}]")
        if node.inode is not None:
            cap = fs.bs // POINTER_SIZE
            print(f"i-node       : bloco {self.bnum(node.inode)}"
                  + ("" if node.is_dir else f" → índices [{self.blist(node.blocks)}] "
                                            f"({len(node.blocks)}/{cap} ponteiros usados)"))
        print(f"Criado em    : {node.ctime:%Y-%m-%d %H:%M:%S}")
        print(f"Modificado em: {node.mtime:%Y-%m-%d %H:%M:%S}")

    def cmd_write(self, args, append=False):
        pos, opts = parse_opts(args, flags=("--append", "-a"))
        if len(pos) < 2:
            raise FSError("uso: write <arquivo> <texto> [--append]")
        append = append or "--append" in opts or "-a" in opts
        node = self.fs.write(pos[0], " ".join(pos[1:]), append=append)
        self.ok(f"{'Conteúdo acrescentado' if append else 'Conteúdo gravado'}: {node.path} "
                f"({fmt_size(node.size)}) → {self.describe_alloc(node)}")

    def cmd_append(self, args):
        self.cmd_write(args, append=True)

    def cmd_resize(self, args):
        pos, opts = parse_opts(args, valued=("--size", "-s"))
        size = opts.get("--size", opts.get("-s"))
        if size is None and len(pos) == 2:
            size = pos.pop()
        if len(pos) != 1 or size is None:
            raise FSError("uso: resize <arquivo> --size <tamanho>")
        node = self.fs.resize(pos[0], parse_size(size))
        self.ok(f"Arquivo redimensionado: {node.path} ({fmt_size(node.size)}) → {self.describe_alloc(node)}")

    def cmd_mv(self, args):
        if len(args) != 2:
            raise FSError("uso: mv <origem> <destino>")
        node = self.fs.move(args[0], args[1])
        self.ok(f"Movido para: {node.path}")

    def cmd_rm(self, args):
        pos, opts = parse_opts(args, flags=("-r", "-rf", "-R"))
        if not pos:
            raise FSError("uso: rm [-r] <caminho>")
        for p in pos:
            node, freed = self.fs.remove(p, recursive=bool(opts))
            self.ok(f"Removido: {node.path} ({freed} bloco(s) liberado(s))")

    def cmd_rmdir(self, args):
        pos, opts = parse_opts(args, flags=("-r", "-R"))
        if not pos:
            raise FSError("uso: rmdir [-r] <dir>")
        for p in pos:
            node, freed = self.fs.remove(p, recursive=bool(opts), only_dir=True)
            self.ok(f"Diretório removido: {node.path} ({freed} bloco(s) liberado(s))")

    def cmd_format(self, args):
        pos, opts = parse_opts(args, valued=("--strategy", "-s", "--block-size", "-b", "--blocks", "-n", "--fit"))
        fs = self.fs
        strat = opts.get("--strategy", opts.get("-s", fs.strategy))
        strat = STRATEGY_ALIASES.get(strat.lower())
        if strat is None:
            raise FSError("estratégia inválida (use contigua, encadeada ou indexada)")
        bs = parse_size(opts.get("--block-size", opts.get("-b", str(fs.bs))))
        try:
            n = int(opts.get("--blocks", opts.get("-n", fs.nblocks)))
        except ValueError:
            raise FSError("--blocks deve ser um número inteiro")
        fit = opts.get("--fit", fs.fit)
        self.fs = FileSystem(strat, bs, n, fit)
        self.ok(f"Disco formatado: {n} blocos x {fmt_size(bs)} = {fmt_size(n * bs)} | "
                f"Alocação {STRATEGY_NAMES[strat]}" + (f" ({fit}-fit)" if strat == "contigua" else ""))

    def cmd_status(self, args):
        _, opts = parse_opts(args, flags=("--details", "-d"))
        details = bool(opts)
        print("\n".join(self.header(details)))
        print()
        if details:
            print("\n".join(self.block_listing()))
            print()
            print("\n".join(self.frag_report(True)))
            print()
            print("\n".join(self.graphic_map()))
        else:
            print("\n".join(self.graphic_map()))
            print()
            print("\n".join(self.frag_report(False)))

    def cmd_map(self, args):
        print("\n".join(self.graphic_map()))

    def cmd_frag(self, args):
        print("\n".join(self.frag_report(True)))

    def cmd_fat(self, args):
        fs = self.fs
        if fs.strategy != "encadeada":
            raise FSError("a tabela FAT só existe na alocação encadeada (format --strategy encadeada)")
        print(self.s("[TABELA FAT]", "1"))
        print("Bloco | Próximo | Dono")
        for b in range(fs.nblocks):
            k = fs.kind[b]
            nxt = {FREE: "livre", SUPER: "reserv."}.get(k)
            if nxt is None:
                nxt = "EOF" if fs.next[b] == EOF else self.bnum(fs.next[b])
            owner = fs.owner[b].path if fs.owner[b] is not None and k == DATA else ("superbloco" if k == SUPER else "")
            print(f"  {self.bnum(b):>3} | {nxt:>7} | {owner}")
        for f in fs.files():
            if f.blocks:
                print(f"Entrada de diretório: {f.path} → primeiro bloco {self.bnum(f.blocks[0])}")

    def cmd_compact(self, args):
        before = self.fs.external_frag()
        moved = self.fs.compact()
        after = self.fs.external_frag()
        self.ok(f"Compactação concluída: {moved} bloco(s) movido(s). Lacunas livres: "
                f"{len(before['holes'])} → {len(after['holes'])} | maior lacuna: "
                f"{before['largest']} → {after['largest']} bloco(s)")

    def cmd_run(self, args):
        if not args:
            raise FSError("uso: run <arquivo>")
        try:
            with open(args[0], encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as e:
            raise FSError(f"não foi possível ler '{args[0]}': {e}")
        return self.run_lines(lines)

    def cmd_demo(self, args):
        names = [STRATEGY_ALIASES.get(a.lower(), a) for a in args] or list(DEMOS)
        for name in names:
            if name not in DEMOS:
                raise FSError(f"demo desconhecida: {name} (use {', '.join(DEMOS)})")
            title = f" DEMONSTRAÇÃO: {STRATEGY_NAMES[name]} "
            print("\n" + self.s(f"{title:=^78}", "1;35"))
            if not self.run_lines(DEMOS[name]):
                return False

    def cmd_clear(self, args):
        os.system("cls" if os.name == "nt" else "clear")

    def cmd_echo(self, args):
        print(" ".join(args))

    def cmd_exit(self, args):
        return False


DEMOS = {
    "indexada": [
        "# Exemplos 1.1 e 1.2 — árvore hierárquica + alocação indexada (i-node)",
        "format --strategy indexada --block-size 4KB --blocks 16",
        "mkdir /sistema",
        "mkdir /sistema/logs",
        "create /sistema/logs/app.log --size 10KB",
        "tree",
        "fs_status --details",
        "# CRUD: leitura, atualização, renomeação e remoção",
        "cd /sistema",
        "create notas.txt --content \"Olá, sistema de arquivos!\"",
        "cat notas.txt",
        "append notas.txt \" Linha acrescentada.\"",
        "cat /sistema/notas.txt",
        "mv notas.txt logs/notas_v2.txt",
        "resize logs/app.log --size 13KB",
        "stat logs/app.log",
        "cd ..",
        "tree",
        "rm /sistema/logs/notas_v2.txt",
        "fs_status",
    ],
    "contigua": [
        "# Alocação contígua: provocando fragmentação externa e resolvendo com compactação",
        "format --strategy contigua --block-size 4KB --blocks 16 --fit first",
        "create /a.txt --size 8KB",
        "create /b.txt --size 10KB",
        "create /c.txt --size 6KB",
        "create /d.txt --size 12KB",
        "create /e.txt --size 5KB",
        "rm /b.txt",
        "rm /d.txt",
        "fs_status",
        "# 9 blocos livres, mas nenhuma lacuna com 5 blocos contíguos:",
        "create /grande.bin --size 20KB",
        "fs_status --details",
        "compact",
        "create /grande.bin --size 20KB",
        "fs_status",
    ],
    "encadeada": [
        "# Alocação encadeada (FAT): arquivos podem ocupar blocos dispersos",
        "format --strategy encadeada --block-size 1KB --blocks 24",
        "mkdir -p /home/user",
        "create /home/user/x.txt --size 3KB",
        "create /home/user/y.txt --size 2.5KB",
        "create /home/user/z.txt --size 1KB",
        "rm /home/user/y.txt",
        "create /home/user/doc.txt --size 5.2KB",
        "stat /home/user/doc.txt",
        "fat",
        "fs_status --details",
    ],
}


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulador de Sistema de Arquivos — Etapa 1")
    p.add_argument("script", nargs="?", help="arquivo com comandos a executar (um por linha)")
    p.add_argument("-s", "--strategy", default="indexada", help="contigua | encadeada | indexada")
    p.add_argument("-b", "--block-size", default="4KB", help="tamanho do bloco (ex.: 512B, 1KB, 4KB)")
    p.add_argument("-n", "--blocks", type=int, default=16, help="número total de blocos")
    p.add_argument("--fit", choices=["first", "best", "worst"], default="first",
                   help="política da alocação contígua")
    p.add_argument("--demo", nargs="?", const="all", help="executa demonstrações (all|indexada|contigua|encadeada)")
    p.add_argument("--no-color", action="store_true", help="desativa cores ANSI")
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
        p.error("estratégia inválida (use contigua, encadeada ou indexada)")
    try:
        fs = FileSystem(strategy, parse_size(a.block_size), a.blocks, a.fit)
    except FSError as e:
        p.error(str(e))

    color = not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    shell = Shell(fs, color)

    if a.demo:
        shell.execute("demo" if a.demo == "all" else f"demo {a.demo}")
    elif a.script:
        shell.execute(f"run {shlex.quote(a.script)}")
    else:
        shell.repl()


if __name__ == "__main__":
    main()
