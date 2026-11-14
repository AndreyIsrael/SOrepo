#!/usr/bin/env python3
import argparse
import getpass
import hashlib
import hmac
import os
import re
import secrets
import shlex
import sys
from datetime import datetime

from fs_sim import STRATEGY_ALIASES, FileSystem, FSError, Shell, fmt_size, parse_opts, parse_size
from io_sim import RAID_LEVELS, IOShell, Storage, get_alg

KERNEL, USER = "MODO_KERNEL", "MODO_USUARIO"
ROOT, ADMIN = "root", "admin"
PBKDF2_ITERS = 100_000
KEY_ITERS = 50_000
UMASK = 0o022
STICKY = 0o1000
PERM_BIT = {"r": 4, "w": 2, "x": 1}
NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

ACTIONS = {
    (False, "r"): ("LEITURA", "leitura"),
    (False, "w"): ("ESCRITA", "escrita"),
    (False, "x"): ("EXECUÇÃO", "execução"),
    (True, "r"): ("LISTAGEM", "listagem (r)"),
    (True, "w"): ("ESCRITA NO DIRETÓRIO", "escrita (criar/remover entradas)"),
    (True, "x"): ("TRAVESSIA", "travessia (x)"),
}

SIGNATURES = {
    "EICAR-Test-File": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    "Shell.ForkBomb": b":(){ :|:& };:",
    "Trojan.Wiper": b"rm -rf --no-preserve-root /",
    "Backdoor.ShadowDump": b"chmod 777 /etc/shadow",
    "Rootkit.SimKit": b"\xde\xad\xbe\xef\x13\x37ROOTKIT",
}

MAGIC = b"SENC"
HEADER = 4 + 1 + 16 + 16 + 8 + 32

OPEN_CMDS = {"login", "help", "?", "exit", "quit", "clear", "echo", "whoami", "mode"}
KERNEL_CMDS = {
    "format", "compact", "defrag", "disk", "raid", "raid_fail", "raid_test", "raid_replace",
    "wear", "ssd_stress", "queue", "flush", "head", "pending", "io_load", "demo", "demo2", "demo3",
    "useradd", "userdel", "groupadd", "groupdel", "usermod", "chown", "logs", "disk_tamper",
    "inject_virus",
}


class AccessDenied(FSError):
    pass


class CryptoError(FSError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def derive_keys(key, salt):
    dk = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, KEY_ITERS, dklen=64)
    return dk[:32], dk[32:]


def keystream_xor(key, nonce, data):
    out = bytearray(len(data))
    for i in range(0, len(data), 32):
        ks = hashlib.sha256(key + nonce + (i // 32).to_bytes(8, "big")).digest()
        chunk = data[i:i + 32]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def encrypt_blob(plain, key, flag):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    ek, mk = derive_keys(key, salt)
    kcv = hashlib.sha256(mk + b"kcv").digest()[:8]
    ct = keystream_xor(ek, nonce, plain)
    tag = hmac.new(mk, MAGIC + flag + salt + nonce + ct, "sha256").digest()
    return MAGIC + flag + salt + nonce + kcv + tag + ct


def decrypt_blob(blob, key):
    if len(blob) < HEADER or blob[:4] != MAGIC:
        raise CryptoError("cabeçalho de criptografia ausente ou corrompido nos blocos físicos")
    flag, salt, nonce = blob[4:5], blob[5:21], blob[21:37]
    kcv, tag, ct = blob[37:45], blob[45:77], blob[77:]
    ek, mk = derive_keys(key, salt)
    if not hmac.compare_digest(kcv, hashlib.sha256(mk + b"kcv").digest()[:8]):
        raise CryptoError("chave incorreta")
    if not hmac.compare_digest(tag, hmac.new(mk, MAGIC + flag + salt + nonce + ct, "sha256").digest()):
        raise CryptoError("falha de integridade (HMAC): os blocos cifrados foram alterados no disco")
    return flag, keystream_xor(ek, nonce, ct)


def find_signature(data):
    for name, sig in SIGNATURES.items():
        i = data.find(sig)
        if i >= 0:
            return name, i
    return None


def masked_input(prompt):
    if not sys.stdin.isatty():
        return input(prompt)
    try:
        import termios
        import tty
    except ImportError:
        try:
            import msvcrt
        except ImportError:
            return getpass.getpass(prompt)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        buf = []
        while True:
            ch = msvcrt.getwch()
            if ch in "\r\n":
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\b":
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
            elif ch >= " ":
                buf.append(ch)
                sys.stdout.write("*")
            sys.stdout.flush()
        print()
        return "".join(buf)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf, raw = [], b""
    try:
        tty.setraw(fd)
        while True:
            raw += os.read(fd, 1)
            try:
                ch = raw.decode("utf-8")
            except UnicodeDecodeError:
                if len(raw) < 4:
                    continue
                ch = ""
            raw = b""
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x04" and not buf:
                raise EOFError
            if ch in ("\x7f", "\b"):
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
            elif ch and ch >= " ":
                buf.append(ch)
                sys.stdout.write("*")
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\n")
        sys.stdout.flush()
    return "".join(buf)


class Account:
    def __init__(self, name, uid, group, groups=(), home=None):
        self.name = name
        self.uid = uid
        self.group = group
        self.groups = set(groups) - {group}
        self.home = home or f"/home/{name}"
        self.hash = None
        self.locked = False
        self.fails = 0

    def set_password(self, password):
        salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
        self.hash = f"$pbkdf2-sha256${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"

    def check_password(self, password):
        try:
            _, _, iters, salt, digest = self.hash.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        except (AttributeError, ValueError):
            return False
        return hmac.compare_digest(dk.hex(), digest)


class SecStorage(Storage):
    verbose = True

    def attach(self, fs):
        super().attach(fs)
        self.rebaseline()

    def rebaseline(self):
        self.hashes = {lba: sha256(blob) for lba, blob in self.image.items()}

    def sync(self, title, forced=(), verbose=True):
        super().sync(title, forced, verbose and self.verbose)
        self.rebaseline()

    def read(self, node, verbose=True):
        return super().read(node, verbose and self.verbose)

    def file_bytes(self, node):
        blob = getattr(node, "cipher", None)
        if blob is not None:
            return blob[:node.size]
        return super().file_bytes(node)

    @staticmethod
    def perm_tag(node):
        acl = sorted(getattr(node, "acl", {}).items())
        return (f"|{getattr(node, 'owner', '?')}:{getattr(node, 'group', '?')}|"
                f"{getattr(node, 'mode', 0):04o}|acl={acl}|"
                f"enc={int(getattr(node, 'cipher', None) is not None)}").encode("utf-8")

    def meta_bytes(self, node):
        base = super().meta_bytes(node).rstrip(b"\0")
        return self.pad(base + self.perm_tag(node))

    def super_bytes(self):
        fs = self.fs
        entries = [(n.path, n.size, n.blocks, self.perm_tag(n).decode()) for n in fs.all_nodes()]
        return self.pad(f"SUPER|{fs.strategy}|{self.perm_tag(fs.root).decode()}|{entries}|{fs.next}"
                        .encode("utf-8"))

    def physical_copies(self, lba):
        arr = self.array
        if arr.level == 1:
            return [(d, arr.raw(d, lba)) for d in range(arr.n) if d not in arr.failed]
        d, off = arr.data_pos(lba)
        if d in arr.failed:
            try:
                blob, _ = arr.read_unit(d, off, arr.new_ops())
            except FSError:
                return []
            return [(d, blob)]
        return [(d, arr.raw(d, off))]

    def read_physical(self, node):
        parts = []
        for b in node.blocks:
            copies = self.physical_copies(b)
            parts.append(copies[0][1] if copies else bytes(self.fs.bs))
        return b"".join(parts)[:node.size]

    def tamper(self, lba, data=None, offset=0):
        arr = self.array
        d, off = (0, lba) if arr.level == 1 else arr.data_pos(lba)
        if d in arr.failed:
            raise FSError(f"Disco {d + 1} está inoperante")
        cur = bytearray(arr.raw(d, off))
        if data is None:
            for i in range(min(16, len(cur))):
                cur[i] ^= 0xFF
        else:
            data = data[:len(cur) - offset]
            cur[offset:offset + len(data)] = data
        arr.store[d][off] = bytes(cur)
        return d, off

    def repair(self, lba):
        arr = self.array
        items = [lba]
        if arr.level in (4, 5):
            items = [m for m in arr.stripe_lbas(lba // arr.dpd()) if m < arr.nblocks]
        blank = self.pad(b"")
        ops = arr.write([(m, self.image.get(m, blank)) for m in items], self.label, verbose=False)
        self.deliver(ops, verbose=False)


HELP3 = """
ETAPA 3 - SEGURANÇA E PROTEÇÃO
  Sessão e privilégios
    login [--user] <nome> [--password X]   autentica (senha digitada com máscara)
    logout | su [usuário] | sudo <comando...>   troca de usuário / elevação temporária
    whoami | id [usuário] | mode            identidade e modo atual (MODO_USUARIO/MODO_KERNEL)
  Identidade (exigem MODO_KERNEL)
    useradd <nome> [--group g] [--groups a,b] [--password X]
    userdel <nome> [-r] | groupadd <g> | groupdel <g>
    usermod <nome> [--add-group g] [--remove-group g] [--primary g] [--lock] [--unlock]
    passwd [usuário] [--password NOVA] [--old ATUAL]
    users | groups                       contas, grupos e membros
  Controle de acesso (rwx para Proprietário/Grupo/Outros + ACL)
    ls [-l] [caminho] | stat <caminho>   mostram dono, grupo e permissões
    chmod <750|u+x,g-w,o=r> <caminho>... | chown <usuário[:grupo]> <caminho> | chgrp <grupo> <caminho>
    getfacl <caminho> | setfacl -m u:nome:rwx|g:grupo:r-x <caminho> | setfacl -x u:nome <caminho> | setfacl -b
    access_matrix [caminho] [--users a,b]   matriz de acesso (objetos x sujeitos)
    acl_trace on|off                     mostra também as verificações permitidas
    exec <script>                        executa um script do sistema de arquivos (exige r+x)
    format ... --bare                    formata sem a estrutura padrão (/etc, /home, /sistema, /tmp)
  Criptografia em repouso
    encrypt_file <arq> --key K | decrypt_file <arq> --key K
    write_file <arq> <texto> --key K     grava já criptografado
    cat <arq> --key K                    lê e decifra a partir dos blocos físicos
  Integridade / antivírus
    antivirus_scan [caminho] [--repair] [--quarantine]
    disk_tamper <arq> [--block N] [--data texto] | disk_tamper --lba N   ataque: escrita direta no disco
    inject_virus <arq> [--sig nome]      ataque: grava assinatura maliciosa direto no bloco
    logs [--tail N] [--user nome]        trilha de auditoria (MODO_KERNEL)
    io_log on|off                        mostra/oculta as mensagens de E/S da etapa 2
    demo3                                demonstração da etapa 3
"""

DEMOS3 = [
    "# Preparação feita pelo root (MODO_KERNEL)",
    "io_log off",
    "passwd root --password root",
    "format --strategy indexada --block-size 4KB --blocks 64",
    "groupadd devs",
    "groupadd qa",
    "useradd carlos --group devs --password Carlos@123",
    "useradd ana --group qa --password Ana@2024",
    "users",
    "cat /etc/shadow",
    "ls -l /sistema",
    "# Exemplo 3.1 - autenticação, modos de execução e ACL",
    "login --user carlos --password Carlos@123",
    "read_file /sistema/config.sys",
    "cat /etc/shadow",
    "format",
    "sudo --password Carlos@123 format",
    "cd /home/carlos",
    "create notas.txt --content \"rascunho do projeto\"",
    "chmod 640 notas.txt",
    "setfacl -m u:ana:r-- notas.txt",
    "setfacl -m u:ana:--x /home/carlos",
    "ls -l",
    "getfacl notas.txt",
    "access_matrix /home",
    "login --user ana --password Ana@2024",
    "ls /home/carlos",
    "cat /home/carlos/notas.txt",
    "write /home/carlos/notas.txt \"alterado pela ana\"",
    "login --user carlos --password errada",
    "# Exemplo 3.2 - criptografia em repouso e antivírus",
    "login --user carlos --password Carlos@123",
    "write_file /home/carlos/segredo.txt \"Senha do cofre: 4242\"",
    "encrypt_file /home/carlos/segredo.txt --key \"MinhaChave123\"",
    "cat /home/carlos/segredo.txt",
    "cat /home/carlos/segredo.txt --key \"ChaveErrada\"",
    "cat /home/carlos/segredo.txt --key \"MinhaChave123\"",
    "create /tmp/deploy.sh --content \"echo iniciando deploy; ls -l /tmp\"",
    "chmod u+x /tmp/deploy.sh",
    "exec /tmp/deploy.sh",
    "create /tmp/limpeza.sh --content \"echo limpando; :(){ :|:& };:\"",
    "chmod +x /tmp/limpeza.sh",
    "exec /tmp/limpeza.sh",
    "create /tmp/teste_av.txt --content \"X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\"",
    "su root --password root",
    "disk_tamper /sistema/logs/app.log --data \"registro apagado pelo invasor\"",
    "inject_virus /home/carlos/notas.txt --sig Rootkit.SimKit",
    "antivirus_scan /",
    "antivirus_scan / --repair --quarantine",
    "antivirus_scan /",
    "logs --tail 12",
    "logout",
    "decrypt_file /home/carlos/segredo.txt --key \"MinhaChave123\"",
    "cat /home/carlos/segredo.txt",
    "login --user root --password root",
    "io_log on",
]


class SecShell(IOShell):
    storage_cls = SecStorage

    def __init__(self, fs, color=True, root_password="root", **kw):
        self.audit = []
        self.stack = [ROOT]
        self.elevated = False
        self.sudo_ok = set()
        self.trace = False
        self.script_depth = 0
        self.exec_depth = 0
        self.bare = False
        self.reset_accounts(root_password)
        self.bootstrap(fs)
        super().__init__(fs, color, **kw)
        self.commands.update({
            "login": self.cmd_login, "logout": self.cmd_logout, "su": self.cmd_su, "sudo": self.cmd_sudo,
            "whoami": self.cmd_whoami, "id": self.cmd_id, "mode": self.cmd_mode,
            "useradd": self.cmd_useradd, "userdel": self.cmd_userdel, "groupadd": self.cmd_groupadd,
            "groupdel": self.cmd_groupdel, "usermod": self.cmd_usermod, "passwd": self.cmd_passwd,
            "users": self.cmd_users, "groups": self.cmd_groups,
            "chmod": self.cmd_chmod, "chown": self.cmd_chown, "chgrp": self.cmd_chgrp,
            "getfacl": self.cmd_getfacl, "setfacl": self.cmd_setfacl, "access_matrix": self.cmd_access_matrix,
            "acl_trace": self.cmd_acl_trace, "exec": self.cmd_exec,
            "encrypt_file": self.cmd_encrypt_file, "decrypt_file": self.cmd_decrypt_file,
            "antivirus_scan": self.cmd_antivirus_scan, "disk_tamper": self.cmd_disk_tamper,
            "inject_virus": self.cmd_inject_virus, "logs": self.cmd_logs, "io_log": self.cmd_io_log,
            "demo3": self.cmd_demo3,
        })
        self.commands = {k: self.guard(k, h) for k, h in self.commands.items()}

    @property
    def user(self):
        return self.stack[-1] if self.stack else None

    @property
    def euser(self):
        return ROOT if self.elevated else self.user

    @property
    def kernel(self):
        return self.euser == ROOT

    @property
    def mode_name(self):
        return KERNEL if self.kernel else USER

    def reset_accounts(self, root_password):
        self.groups = {ADMIN: 0}
        root = Account(ROOT, 0, ADMIN, home="/root")
        root.set_password(root_password)
        self.accounts = {ROOT: root}
        self.next_uid = self.next_gid = 1000

    def groups_of(self, name):
        acc = self.accounts.get(name)
        return {acc.group} | acc.groups if acc else set()

    def primary(self, name):
        acc = self.accounts.get(name)
        return acc.group if acc else "?"

    def log(self, event, detail, level="INFO"):
        self.audit.append((datetime.now(), self.user or "-", self.euser or "-", level, event, detail))

    def guard(self, name, handler):
        def run(args):
            if self.user is None and name not in OPEN_CMDS:
                raise FSError("nenhuma sessão ativa: use 'login --user <nome>'")
            if self.needs_kernel(name, args) and not self.kernel:
                self.deny_privilege(" ".join([name] + list(args)))
                return None
            try:
                return handler(args)
            except AccessDenied:
                return None
            finally:
                self.stamp()
        return run

    def needs_kernel(self, name, args):
        return name in KERNEL_CMDS or (name == "sched" and len(args) == 1)

    def deny_privilege(self, operation):
        user = self.euser
        print(self.s("[SISTEMA DE SEGURANÇA - CONTROLE DE PRIVILÉGIOS]", "1"))
        print(f"Operação    : {operation}  (operação crítica do sistema)")
        print(f"Requer      : {KERNEL} (superusuário root)")
        print(f"Sessão      : '{user}' (Grupo: {self.primary(user)}) | {self.mode_name}")
        print()
        print(self.s(f"[NEGADO]: Privilégios insuficientes. Use 'sudo {operation.split()[0]} ...' "
                     f"(membros do grupo '{ADMIN}') ou 'su root'.", "31;1"))
        print("Tentativa não autorizada registrada nos logs do sistema.")
        self.log("PRIVILEGIO", f"'{operation}' negado em {USER}", "ALERTA")

    def stamp(self, fs=None):
        fs = fs or self.fs
        owner = self.euser or ROOT
        for n in fs.all_nodes(include_root=True):
            if hasattr(n, "owner"):
                continue
            if n is fs.root:
                n.owner, n.group, n.mode = ROOT, ADMIN, 0o755
            else:
                n.owner, n.group = owner, self.primary(owner)
                n.mode = (0o777 if n.is_dir else 0o666) & ~UMASK
            n.acl = {}

    def sys_set(self, node, owner, group, mode):
        node.owner, node.group, node.mode, node.acl = owner, group, mode, getattr(node, "acl", {})

    def sys_mkdir(self, fs, path, owner=ROOT, group=ADMIN, mode=0o755):
        node = fs.mkdir(path, parents=True)
        self.sys_set(node, owner, group, mode)
        return node

    def sys_file(self, fs, path, text, owner=ROOT, group=ADMIN, mode=0o644):
        try:
            node = fs.read(path)
            fs.write(path, text)
        except FSError:
            parent = path.rsplit("/", 1)[0] or "/"
            if parent != "/":
                self.stamp(fs)
                fs.mkdir(parent, parents=True)
            node = fs.create(path, 0, text)
        self.sys_set(node, owner, group, mode)
        return node

    def bootstrap(self, fs):
        self.stamp(fs)
        try:
            for path, mode in (("/etc", 0o755), ("/home", 0o755), ("/root", 0o700), ("/tmp", 0o1777),
                               ("/sistema", 0o755), ("/sistema/logs", 0o755)):
                self.sys_mkdir(fs, path, mode=mode)
            for acc in self.accounts.values():
                if acc.name != ROOT:
                    self.sys_mkdir(fs, acc.home, acc.name, acc.group, 0o750)
            self.sys_file(fs, "/sistema/config.sys", "KERNEL=simos-3.0\nMAX_PROC=64\nSECURE_BOOT=1",
                          mode=0o750)
            self.sys_file(fs, "/sistema/logs/app.log", "[boot] sistema iniciado; servicos ok", mode=0o644)
            self.write_etc(fs)
        except FSError as e:
            print(f"Aviso: estrutura inicial incompleta ({e})")
        self.stamp(fs)
        fs.cwd = fs.root

    def write_etc(self, fs=None):
        fs = fs or self.fs
        accs = sorted(self.accounts.values(), key=lambda a: a.uid)
        passwd = "\n".join(f"{a.name}:x:{a.uid}:{self.groups.get(a.group, '?')}:{a.home}" for a in accs)
        shadow = "\n".join(f"{a.name}:{'!' if a.locked else ''}{a.hash}" for a in accs)
        group = "\n".join(
            f"{g}:x:{gid}:{','.join(a.name for a in accs if g in self.groups_of(a.name))}"
            for g, gid in sorted(self.groups.items(), key=lambda x: x[1]))
        self.sys_file(fs, "/etc/passwd", passwd, mode=0o644)
        self.sys_file(fs, "/etc/group", group, mode=0o644)
        self.sys_file(fs, "/etc/shadow", shadow, mode=0o600)

    def bits_for(self, node, user):
        if user == ROOT:
            return 7, "Superusuário (root)"
        if node.owner == user:
            return (node.mode >> 6) & 7, "Proprietário"
        if ("u", user) in node.acl:
            return node.acl[("u", user)], f"ACL user:{user}"
        gs = self.groups_of(user)
        bits, hits = 0, []
        if node.group in gs:
            bits |= (node.mode >> 3) & 7
            hits.append("Grupo")
        for (kind, name), b in sorted(node.acl.items()):
            if kind == "g" and name in gs:
                bits |= b
                hits.append(f"ACL group:{name}")
        if hits:
            return bits, " + ".join(hits)
        return node.mode & 7, "Outros"

    def allowed(self, node, p, user=None):
        return bool(self.bits_for(node, user or self.euser)[0] & PERM_BIT[p])

    @staticmethod
    def rwx(bits):
        return "".join(c if bits & PERM_BIT[c] else "-" for c in "rwx")

    def mode_str(self, node):
        m = node.mode
        s = ("d" if node.is_dir else "-") + self.rwx(m >> 6) + self.rwx(m >> 3) + self.rwx(m)
        if m & STICKY:
            s = s[:-1] + ("t" if m & 1 else "T")
        return s + ("+" if node.acl else "")

    @staticmethod
    def octal(node):
        return f"{node.mode & 0o7777:o}".rjust(3, "0")

    def acl_text(self, node):
        return ", ".join(f"{'user' if k == 'u' else 'group'}:{n}:{self.rwx(b)}"
                         for (k, n), b in sorted(node.acl.items()))

    def acl_box(self, node, p, granted):
        user = self.euser
        action = ACTIONS[(node.is_dir, p)]
        bits, cls = self.bits_for(node, user)
        print(self.s("[SISTEMA DE SEGURANÇA - VERIFICAÇÃO DE ACL]", "1"))
        print(f"Objeto      : {node.path}")
        print(f"Proprietário: {node.owner} (Grupo: {node.group})")
        print(f"Permissões  : {self.mode_str(node).lstrip('d-')[:9]} ({self.octal(node)})")
        if node.acl:
            print(f"ACL         : {self.acl_text(node)}")
        print(f"Ação Pedida : {action[0]} por '{user}' (Grupo: {self.primary(user)})")
        print(f"Regra usada : {cls} -> {self.rwx(bits)}")
        print()
        if granted:
            print(self.s(f"[PERMITIDO]: acesso de {action[1]} concedido a '{user}'.", "32"))

    def deny(self, node, p):
        user = self.euser
        self.acl_box(node, p, False)
        action = ACTIONS[(node.is_dir, p)]
        print(self.s(f"[NEGADO]: O usuário '{user}' não possui permissão de {action[1]} no objeto "
                     f"'{node.path}'.", "31;1"))
        print("Tentativa não autorizada registrada nos logs do sistema.")
        self.log("ACESSO_NEGADO", f"{action[0]} em {node.path} ({self.mode_str(node)})", "ALERTA")
        raise AccessDenied("acesso negado")

    def deny_owner(self, node, what):
        print(self.s("[SISTEMA DE SEGURANÇA - VERIFICAÇÃO DE PROPRIEDADE]", "1"))
        print(f"Objeto      : {node.path}")
        print(f"Proprietário: {node.owner} (Grupo: {node.group})")
        print(f"Ação Pedida : {what} por '{self.euser}'")
        print()
        print(self.s(f"[NEGADO]: Apenas o proprietário ('{node.owner}') ou o superusuário pode {what} "
                     f"de '{node.path}'.", "31;1"))
        print("Tentativa não autorizada registrada nos logs do sistema.")
        self.log("ACESSO_NEGADO", f"{what} em {node.path}", "ALERTA")
        raise AccessDenied("acesso negado")

    def require(self, node, perms="", traverse=True):
        if traverse:
            chain, a = [], node.parent
            while a is not None:
                chain.append(a)
                a = a.parent
            for d in reversed(chain):
                if not self.allowed(d, "x"):
                    self.deny(d, "x")
        for p in perms:
            if not self.allowed(node, p):
                self.deny(node, p)
        if self.trace and perms:
            for p in perms:
                self.acl_box(node, p, True)

    def require_owner(self, node, what):
        self.require(node)
        if not (self.kernel or node.owner == self.euser):
            self.deny_owner(node, what)

    def require_unlink(self, node):
        parent = node.parent
        self.require(parent, "wx")
        if parent.mode & STICKY and self.euser not in (ROOT, node.owner, parent.owner):
            print(self.s(f"[NEGADO]: '{parent.path}' tem sticky bit (t): apenas o dono de '{node.path}' "
                         f"('{node.owner}') pode removê-lo ou renomeá-lo.", "31;1"))
            self.log("ACESSO_NEGADO", f"remoção em diretório sticky {node.path}", "ALERTA")
            raise AccessDenied("acesso negado")

    @staticmethod
    def no_cipher(node):
        if getattr(node, "cipher", None) is not None:
            raise FSError(f"'{node.path}' está criptografado: use 'decrypt_file' antes de alterá-lo")

    def ask_secret(self, value, prompt="Senha: "):
        if value is not None:
            print(f"{prompt}{'*' * len(value)}")
            return value
        if self.script_depth:
            raise FSError("em scripts informe a senha/chave com --password/--key")
        try:
            return masked_input(prompt)
        except (KeyboardInterrupt, EOFError):
            raise FSError("operação cancelada")

    def execute(self, line, echo=False):
        stripped = line.strip()
        if stripped.startswith("./"):
            line = "exec " + stripped[2:]
        return super().execute(line, echo)

    def run_lines(self, lines):
        self.script_depth += 1
        try:
            return super().run_lines(lines)
        finally:
            self.script_depth -= 1

    def prompt(self):
        if self.user is None:
            return self.s("(sem sessão)", "33;1") + " login> "
        color = "31;1" if self.kernel else "32;1"
        return (self.s(f"{self.user}@simos", color) + ":" + self.s(self.fs.cwd.path, "34;1")
                + ("# " if self.kernel else "$ "))

    def repl(self):
        try:
            import readline
        except ImportError:
            pass
        self.banner()
        while True:
            try:
                line = input(self.prompt())
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not self.execute(line):
                break

    def banner(self):
        print(self.s("Simulador de SO - Etapa 3: Segurança e Proteção (integra as etapas 1 e 2)", "1"))
        super().banner()
        print(f"Sessão inicial: root ({KERNEL}). Crie usuários com 'useradd' e entre com 'login'.")
        print("Digite 'help' para ver os comandos ou 'demo3' para a demonstração da etapa 3.\n")

    def cmd_help(self, args):
        super().cmd_help(args)
        print(HELP3)

    def cmd_login(self, args):
        pos, opts = parse_opts(args, valued=("--user", "-u", "--password", "-p"))
        name = opts.get("--user", opts.get("-u")) or (pos[0] if pos else None)
        if not name:
            if self.script_depth:
                raise FSError("uso: login --user <nome> [--password X]")
            name = input("Usuário: ").strip()
        pw = self.ask_secret(opts.get("--password", opts.get("-p")))
        acc = self.accounts.get(name)
        if acc is not None and acc.locked:
            self.log("LOGIN_FALHOU", f"conta bloqueada '{name}'", "ALERTA")
            raise FSError(f"conta '{name}' bloqueada após tentativas inválidas (root: usermod {name} --unlock)")
        if acc is None or not acc.check_password(pw):
            msg = "Falha de autenticação: usuário ou senha inválidos."
            if acc is not None:
                acc.fails += 1
                if acc.fails >= 3 and name != ROOT:
                    acc.locked = True
                    msg += f" Conta '{name}' bloqueada após 3 tentativas."
                else:
                    msg += f" ({acc.fails}/3 tentativas)"
            self.log("LOGIN_FALHOU", f"usuário '{name}'", "ALERTA")
            print(self.s(msg, "31;1"))
            print("Tentativa registrada nos logs do sistema.")
            return
        acc.fails = 0
        self.stack, self.elevated, self.sudo_ok = [name], False, set()
        self.log("LOGIN", f"'{name}' autenticado")
        self.go_home(acc)
        self.ok(f"Autenticado com sucesso. Usuário: '{name}' | Grupo: '{acc.group}' | Modo: {self.mode_name}")

    def go_home(self, acc):
        try:
            node = self.fs.resolve(acc.home)
            if node.is_dir and all(self.allowed(a, "x", acc.name) for a in self.chain(node)):
                self.fs.cwd = node
                return
        except FSError:
            pass
        self.fs.cwd = self.fs.root

    @staticmethod
    def chain(node):
        out = []
        while node is not None:
            out.append(node)
            node = node.parent
        return out

    def cmd_logout(self, args):
        if not self.stack:
            raise FSError("nenhuma sessão ativa")
        old = self.stack.pop()
        self.log("LOGOUT", f"'{old}' encerrou a sessão")
        if self.stack:
            self.ok(f"Sessão de '{old}' encerrada. Retornando para '{self.user}' ({self.mode_name}).")
        else:
            self.fs.cwd = self.fs.root
            self.ok(f"Sessão de '{old}' encerrada. Use 'login' para entrar novamente.")

    def cmd_su(self, args):
        pos, opts = parse_opts(args, valued=("--password", "-p"))
        target = pos[0] if pos else ROOT
        acc = self.accounts.get(target)
        if acc is None:
            raise FSError(f"usuário inexistente: '{target}'")
        if not self.kernel:
            pw = self.ask_secret(opts.get("--password", opts.get("-p")))
            if acc.locked or not acc.check_password(pw):
                self.log("SU_FALHOU", f"'{self.user}' -> '{target}'", "ALERTA")
                print(self.s("su: falha de autenticação. Tentativa registrada nos logs do sistema.", "31;1"))
                return
        self.stack.append(target)
        self.log("SU", f"'{self.stack[-2]}' -> '{target}'")
        self.ok(f"Usuário: '{target}' | Grupo: '{acc.group}' | Modo: {self.mode_name}  ('logout' para voltar)")

    def cmd_sudo(self, args):
        args = list(args)
        pw = None
        if args and args[0] in ("--password", "-p"):
            if len(args) < 2:
                raise FSError("a opção --password requer um valor")
            pw, args = args[1], args[2:]
        if not args:
            raise FSError("uso: sudo [--password X] <comando> [args...]")
        user = self.user
        if user != ROOT:
            if ADMIN not in self.groups_of(user):
                self.log("SUDO_NEGADO", f"'{user}' não pertence ao grupo {ADMIN}: {' '.join(args)}", "ALERTA")
                print(self.s(f"[NEGADO]: '{user}' não está no grupo de administradores ('{ADMIN}'). "
                             f"Este incidente será registrado nos logs do sistema.", "31;1"))
                return
            if user not in self.sudo_ok:
                given = self.ask_secret(pw, f"[sudo] senha para {user}: ")
                if not self.accounts[user].check_password(given):
                    self.log("SUDO_FALHOU", f"senha incorreta de '{user}'", "ALERTA")
                    print(self.s("sudo: senha incorreta. Tentativa registrada.", "31;1"))
                    return
                self.sudo_ok.add(user)
        handler = self.commands.get(args[0].lower())
        if handler is None:
            raise FSError(f"comando desconhecido: '{args[0]}'")
        self.log("SUDO", " ".join(args))
        print(self.s(f"[sudo] '{user}' executando '{args[0]}' em {KERNEL}", "2"))
        prev, self.elevated = self.elevated, True
        try:
            return handler(args[1:])
        finally:
            self.elevated = prev

    def cmd_whoami(self, args):
        if self.user is None:
            print("(nenhuma sessão)")
            return
        tag = f" (via sudo, real: {self.user})" if self.elevated else ""
        print(f"{self.euser}{tag} | Grupo: {self.primary(self.euser)} | Modo: {self.mode_name}")

    def cmd_mode(self, args):
        if self.user is None:
            print("Sem sessão ativa.")
            return
        print(f"Modo de execução atual: {self.mode_name}")
        print("MODO_KERNEL  = root: acesso irrestrito, operações críticas liberadas")
        print("MODO_USUARIO = usuário comum: sujeito às permissões rwx/ACL; operações críticas exigem sudo/su")

    def cmd_id(self, args):
        name = args[0] if args else self.euser
        acc = self.accounts.get(name)
        if acc is None:
            raise FSError(f"usuário inexistente: '{name}'")
        gs = [acc.group] + sorted(acc.groups)
        print(f"uid={acc.uid}({acc.name}) gid={self.groups.get(acc.group, '?')}({acc.group}) "
              f"grupos=" + ",".join(f"{self.groups.get(g, '?')}({g})" for g in gs))

    def valid_name(self, name):
        if not NAME_RE.match(name):
            raise FSError(f"nome inválido: '{name}' (use letras minúsculas, dígitos, _ ou -)")

    def need_group(self, g):
        if g not in self.groups:
            raise FSError(f"grupo inexistente: '{g}' (crie com groupadd)")

    def cmd_groupadd(self, args):
        if len(args) != 1:
            raise FSError("uso: groupadd <grupo>")
        g = args[0]
        self.valid_name(g)
        if g in self.groups:
            raise FSError(f"grupo já existe: '{g}'")
        self.groups[g] = self.next_gid
        self.next_gid += 1
        self.write_etc()
        self.log("GROUPADD", g)
        self.ok(f"Grupo '{g}' criado (gid {self.groups[g]})")

    def cmd_groupdel(self, args):
        if len(args) != 1:
            raise FSError("uso: groupdel <grupo>")
        g = args[0]
        self.need_group(g)
        if g == ADMIN or any(a.group == g for a in self.accounts.values()):
            raise FSError(f"'{g}' é grupo primário de algum usuário e não pode ser removido")
        del self.groups[g]
        for a in self.accounts.values():
            a.groups.discard(g)
        self.write_etc()
        self.log("GROUPDEL", g)
        self.ok(f"Grupo '{g}' removido")

    def cmd_useradd(self, args):
        pos, opts = parse_opts(args, valued=("--group", "-g", "--groups", "-G", "--password", "-p", "--home"))
        if len(pos) != 1:
            raise FSError("uso: useradd <nome> [--group g] [--groups a,b] [--password X]")
        name = pos[0]
        self.valid_name(name)
        if name in self.accounts:
            raise FSError(f"usuário já existe: '{name}'")
        group = opts.get("--group", opts.get("-g"))
        extra = [g for g in opts.get("--groups", opts.get("-G", "")).split(",") if g]
        for g in extra + ([group] if group else []):
            self.need_group(g)
        pw = self.ask_secret(opts.get("--password", opts.get("-p")), f"Senha para {name}: ")
        if len(pw) < 4:
            raise FSError("senha muito curta (mínimo 4 caracteres)")
        if group is None:
            group = name
            if group not in self.groups:
                self.groups[group] = self.next_gid
                self.next_gid += 1
        acc = Account(name, self.next_uid, group, extra, opts.get("--home"))
        self.next_uid += 1
        acc.set_password(pw)
        self.accounts[name] = acc
        self.sys_mkdir(self.fs, acc.home, name, group, 0o750)
        self.write_etc()
        self.log("USERADD", f"{name} (grupo {group})")
        self.ok(f"Usuário '{name}' criado: uid={acc.uid} | grupo '{group}'"
                + (f" | grupos extras: {', '.join(extra)}" if extra else "") + f" | home {acc.home} (750)")
        _, _, iters, salt, digest = acc.hash.split("$")
        print(f"  Senha armazenada com PBKDF2-HMAC-SHA256 ({iters} iterações, salt aleatório de 128 bits):")
        print(f"  salt={salt}  hash={digest[:32]}...")

    def cmd_userdel(self, args):
        pos, opts = parse_opts(args, flags=("-r",))
        if len(pos) != 1:
            raise FSError("uso: userdel <nome> [-r]")
        name = pos[0]
        if name == ROOT:
            raise FSError("o usuário root não pode ser removido")
        acc = self.accounts.get(name)
        if acc is None:
            raise FSError(f"usuário inexistente: '{name}'")
        if name in self.stack:
            raise FSError(f"'{name}' está com sessão ativa (faça logout antes)")
        del self.accounts[name]
        if "-r" in opts:
            try:
                self.fs.remove(acc.home, recursive=True)
            except FSError:
                pass
        self.write_etc()
        self.log("USERDEL", name)
        self.ok(f"Usuário '{name}' removido" + (" (home apagado)" if "-r" in opts else ""))

    def cmd_usermod(self, args):
        pos, opts = parse_opts(args, valued=("--add-group", "-a", "--remove-group", "-r", "--primary"),
                               flags=("--lock", "--unlock"))
        if len(pos) != 1 or not opts:
            raise FSError("uso: usermod <nome> [--add-group g] [--remove-group g] [--primary g] [--lock|--unlock]")
        acc = self.accounts.get(pos[0])
        if acc is None:
            raise FSError(f"usuário inexistente: '{pos[0]}'")
        for key in ("--add-group", "-a"):
            if key in opts:
                self.need_group(opts[key])
                if opts[key] != acc.group:
                    acc.groups.add(opts[key])
        for key in ("--remove-group", "-r"):
            if key in opts:
                acc.groups.discard(opts[key])
        if "--primary" in opts:
            self.need_group(opts["--primary"])
            acc.groups.add(acc.group)
            acc.group = opts["--primary"]
            acc.groups.discard(acc.group)
        if "--lock" in opts:
            acc.locked = True
        if "--unlock" in opts:
            acc.locked, acc.fails = False, 0
        self.write_etc()
        self.log("USERMOD", " ".join(args))
        self.ok(f"Usuário '{acc.name}': grupo '{acc.group}' | grupos extras: "
                f"{', '.join(sorted(acc.groups)) or '-'} | {'BLOQUEADO' if acc.locked else 'ativo'}")

    def cmd_passwd(self, args):
        pos, opts = parse_opts(args, valued=("--password", "-p", "--old"))
        target = pos[0] if pos else self.user
        acc = self.accounts.get(target)
        if acc is None:
            raise FSError(f"usuário inexistente: '{target}'")
        if target != self.user and not self.kernel:
            self.deny_privilege(f"passwd {target}")
            return
        if not self.kernel:
            old = self.ask_secret(opts.get("--old"), "Senha atual: ")
            if not acc.check_password(old):
                self.log("PASSWD_FALHOU", target, "ALERTA")
                raise FSError("senha atual incorreta")
        pw = self.ask_secret(opts.get("--password", opts.get("-p")), "Nova senha: ")
        if len(pw) < 4:
            raise FSError("senha muito curta (mínimo 4 caracteres)")
        acc.set_password(pw)
        self.write_etc()
        self.log("PASSWD", f"senha de '{target}' alterada")
        self.ok(f"Senha de '{target}' atualizada (novo salt + hash PBKDF2-SHA256 gravados em /etc/shadow)")

    def cmd_users(self, args):
        print(f"{'Usuário':<10}{'uid':>5}  {'Grupo':<10}{'Grupos extras':<16}{'Estado':<11}Hash armazenado")
        for a in sorted(self.accounts.values(), key=lambda a: a.uid):
            h = (a.hash[:34] + "...") if self.kernel else "(visível apenas em MODO_KERNEL)"
            print(f"{a.name:<10}{a.uid:>5}  {a.group:<10}{','.join(sorted(a.groups)) or '-':<16}"
                  f"{'BLOQUEADO' if a.locked else 'ativo':<11}{h}")

    def cmd_groups(self, args):
        for g, gid in sorted(self.groups.items(), key=lambda x: x[1]):
            members = [a.name for a in self.accounts.values() if g in self.groups_of(a.name)]
            print(f"{g:<10} gid={gid:<6} membros: {', '.join(members) or '-'}")

    def long_line(self, n):
        name = self.s(n.name + "/", "34;1") if n.is_dir else n.name
        size = "-" if n.is_dir else fmt_size(n.size)
        tag = self.s("  [CRIPTOGRAFADO]", "35") if getattr(n, "cipher", None) is not None else ""
        return f"{self.mode_str(n):<11} {n.owner:<8} {n.group:<8} {size:>9}  {name}{tag}"

    def cmd_ls(self, args):
        pos, _ = parse_opts(args, flags=("-l", "-a", "-la", "-al"))
        node = self.fs.resolve(pos[0] if pos else ".")
        if not node.is_dir:
            self.require(node)
            print(self.long_line(node))
            return
        self.require(node, "r")
        kids = sorted(node.children.values(), key=lambda n: (not n.is_dir, n.name))
        if not kids:
            print("(vazio)")
        for k in kids:
            print(self.long_line(k))

    def cmd_cd(self, args):
        if args:
            node = self.fs.resolve(args[0])
        else:
            acc = self.accounts.get(self.user)
            node = self.fs.resolve(acc.home if acc else "/")
        if not node.is_dir:
            raise FSError(f"'{node.path}' não é um diretório")
        self.require(node, "x")
        self.fs.cwd = node

    def cmd_tree(self, args):
        node = self.fs.resolve(args[0] if args else "/")
        if node.is_dir:
            self.require(node, "r")
        super().cmd_tree(args)

    def cmd_mkdir(self, args):
        pos, opts = parse_opts(args, flags=("-p",))
        for p in pos:
            self.check_mkdir(p, "-p" in opts)
        super().cmd_mkdir(args)

    def check_mkdir(self, path, parents):
        fs = self.fs
        if not parents:
            parent, _ = fs.resolve_parent(path)
            self.require(parent, "wx")
            return
        node = fs.root if path.startswith("/") else fs.cwd
        self.require(node, "x")
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                node = node.parent or node
            elif part in node.children:
                node = node.children[part]
                if not node.is_dir:
                    return
                self.require(node, "x", traverse=False)
            else:
                self.require(node, "wx", traverse=False)
                return

    def cmd_create(self, args):
        pos, _ = parse_opts(args, valued=("--size", "--content", "-s", "-c"))
        for p in pos:
            parent, _ = self.fs.resolve_parent(p)
            self.require(parent, "wx")
        super().cmd_create(args)

    def read_through(self, node, verbose=True):
        data = self.storage.read(node, verbose)
        return b"".join(data[b] for b in node.blocks)[:node.size]

    def cmd_cat(self, args):
        pos, opts = parse_opts(args, valued=("--key", "-k"))
        if not pos:
            raise FSError("uso: cat <arquivo> [--key K]")
        node = self.fs.read(pos[0])
        self.require(node, "r")
        if getattr(node, "cipher", None) is None:
            super().cmd_cat([pos[0]])
            return
        key = opts.get("--key", opts.get("-k"))
        blob = self.read_through(node)
        if key is None:
            print(self.s(f"[CRIPTOGRAFADO] {node.path}: {len(blob)} bytes cifrados nos blocos físicos", "35"))
            print(f"0x{blob[HEADER:HEADER + 24].hex().upper()}... (Encrypted Ciphertext)")
            print(self.s("Use 'cat <arquivo> --key <chave>' para decifrar.", "2"))
            return
        try:
            flag, plain = decrypt_blob(blob, self.ask_secret(key, "Chave: "))
        except CryptoError as e:
            self.log("DECIFRAR_FALHOU", f"{node.path}: {e}", "ALERTA")
            raise
        self.log("DECIFRAR", f"leitura decifrada de {node.path}")
        print(self.s(f"[DECIFRADO EM MEMÓRIA] {node.path} (o disco continua cifrado)", "32"))
        if flag == b"S":
            print(self.s(f"(conteúdo simulado: {len(plain)} bytes)", "2"))
        else:
            print(plain.decode("utf-8", "replace"))

    def cmd_stat(self, args):
        node = self.fs.resolve(args[0] if args else ".")
        self.require(node)
        super().cmd_stat(args)
        print(f"Dono/Grupo   : {node.owner} / {node.group}")
        print(f"Permissões   : {self.mode_str(node)} ({self.octal(node)})")
        if node.acl:
            print(f"ACL          : {self.acl_text(node)}")
        if getattr(node, "cipher", None) is not None:
            print("Criptografia : SIM (fluxo SHA-256/CTR + HMAC-SHA256, chave derivada por PBKDF2)")
        bits, cls = self.bits_for(node, self.euser)
        print(f"Seu acesso   : {self.rwx(bits)} ({cls})")

    def cmd_write(self, args, append=False):
        pos, _ = parse_opts(args, flags=("--append", "-a"))
        if pos:
            node = self.fs.read(pos[0])
            self.require(node, "w")
            self.no_cipher(node)
        super().cmd_write(args, append)

    def cmd_resize(self, args):
        pos, _ = parse_opts(args, valued=("--size", "-s"))
        if pos:
            node = self.fs.read(pos[0])
            self.require(node, "w")
            self.no_cipher(node)
        super().cmd_resize(args)

    def cmd_mv(self, args):
        if len(args) == 2:
            fs = self.fs
            node = fs.resolve(args[0])
            if node is not fs.root:
                self.require_unlink(node)
                try:
                    target = fs.resolve(args[1])
                except FSError:
                    target = None
                dparent = target if target is not None and target.is_dir else fs.resolve_parent(args[1])[0]
                self.require(dparent, "wx")
        super().cmd_mv(args)

    def check_remove(self, path, recursive):
        node = self.fs.resolve(path)
        if node is self.fs.root:
            return
        self.require_unlink(node)
        if node.is_dir and recursive:
            stack = [node]
            while stack:
                d = stack.pop()
                if d.children:
                    self.require(d, "rwx", traverse=False)
                    for c in d.children.values():
                        if c.is_dir:
                            stack.append(c)

    def cmd_rm(self, args):
        pos, opts = parse_opts(args, flags=("-r", "-rf", "-R"))
        for p in pos:
            self.check_remove(p, bool(opts))
        super().cmd_rm(args)

    def cmd_rmdir(self, args):
        pos, opts = parse_opts(args, flags=("-r", "-R"))
        for p in pos:
            self.check_remove(p, bool(opts))
        super().cmd_rmdir(args)

    def cmd_write_file(self, args):
        args = list(args)
        key = None
        for flag in ("--key", "-k"):
            if flag in args:
                i = args.index(flag)
                if i + 1 >= len(args):
                    raise FSError("a opção --key requer um valor")
                key = args[i + 1]
                del args[i:i + 2]
        pos, _ = parse_opts(args, valued=("--size", "-s"))
        if pos:
            try:
                node = self.fs.read(pos[0])
            except FSError:
                node = None
            if node is None:
                self.require(self.fs.resolve_parent(pos[0])[0], "wx")
            else:
                self.require(node, "w")
                self.no_cipher(node)
        super().cmd_write_file(args)
        if key is not None:
            self.storage.sync("write_file", self.forced)
            self.forced = []
            self.cmd_encrypt_file([pos[0], "--key", key])

    def cmd_format(self, args):
        bare = self.bare or "--bare" in args
        Shell.cmd_format(self, [a for a in args if a != "--bare"])
        if bare:
            self.stamp()
        else:
            self.bootstrap(self.fs)
        self.storage.attach(self.fs)
        self.log("FORMAT", " ".join(args) or "padrão")

    def legacy_demo(self, runner, args):
        self.bare = True
        try:
            return runner(args)
        finally:
            self.bare = False

    def cmd_demo(self, args):
        return self.legacy_demo(super().cmd_demo, args)

    def cmd_demo2(self, args):
        return self.legacy_demo(super().cmd_demo2, args)

    def parse_mode(self, spec, cur):
        if re.fullmatch(r"[0-7]{3,4}", spec):
            return int(spec, 8)
        mode = cur
        for clause in spec.split(","):
            m = re.fullmatch(r"([ugoa]*)([+\-=])([rwxt]*)", clause)
            if not m:
                raise FSError(f"modo inválido: '{spec}' (ex.: 750, u+x, g-w, o=r, a+rx, +t)")
            who, op, what = m.groups()
            who = "ugo" if not who or "a" in who else who
            bits = mask = 0
            for w in who:
                shift = {"u": 6, "g": 3, "o": 0}[w]
                mask |= 7 << shift
                for p in what:
                    if p in PERM_BIT:
                        bits |= PERM_BIT[p] << shift
            if "t" in what:
                bits |= STICKY
                mask |= STICKY
            if op == "+":
                mode |= bits
            elif op == "-":
                mode &= ~bits
            else:
                mode = (mode & ~mask) | bits
        return mode

    def cmd_chmod(self, args):
        pos, opts = parse_opts(args, flags=("-R",))
        if len(pos) < 2:
            raise FSError("uso: chmod <modo> <caminho>...   (ex.: chmod 750 arq | chmod u+x,g-w arq)")
        for p in pos[1:]:
            node = self.fs.resolve(p)
            targets = [node] + ([n for n in self.fs.all_nodes() if self.fs._is_ancestor(node, n) and n is not node]
                                if "-R" in opts and node.is_dir else [])
            for n in targets:
                self.require_owner(n, "alterar as permissões")
                old = self.mode_str(n)
                n.mode = self.parse_mode(pos[0], n.mode)
                self.log("CHMOD", f"{n.path}: {old} -> {self.mode_str(n)}")
                self.ok(f"{n.path}: {old} -> {self.mode_str(n)} ({self.octal(n)})")

    def cmd_chown(self, args):
        pos, opts = parse_opts(args, flags=("-R",))
        if len(pos) < 2:
            raise FSError("uso: chown <usuário>[:grupo] <caminho>...")
        owner, _, group = pos[0].partition(":")
        if owner and owner not in self.accounts:
            raise FSError(f"usuário inexistente: '{owner}'")
        if group:
            self.need_group(group)
        for p in pos[1:]:
            node = self.fs.resolve(p)
            targets = [node] + ([n for n in self.fs.all_nodes() if self.fs._is_ancestor(node, n) and n is not node]
                                if "-R" in opts and node.is_dir else [])
            for n in targets:
                n.owner = owner or n.owner
                n.group = group or n.group
                self.log("CHOWN", f"{n.path} -> {n.owner}:{n.group}")
                self.ok(f"{n.path}: dono '{n.owner}', grupo '{n.group}'")

    def cmd_chgrp(self, args):
        if len(args) < 2:
            raise FSError("uso: chgrp <grupo> <caminho>...")
        self.need_group(args[0])
        for p in args[1:]:
            node = self.fs.resolve(p)
            self.require_owner(node, "alterar o grupo")
            if not self.kernel and args[0] not in self.groups_of(self.euser):
                raise FSError(f"'{self.euser}' não pertence ao grupo '{args[0]}'")
            node.group = args[0]
            self.log("CHGRP", f"{node.path} -> {args[0]}")
            self.ok(f"{node.path}: grupo '{args[0]}'")

    def cmd_getfacl(self, args):
        if not args:
            raise FSError("uso: getfacl <caminho>")
        node = self.fs.resolve(args[0])
        self.require(node)
        print(f"# arquivo: {node.path}")
        print(f"# dono: {node.owner}")
        print(f"# grupo: {node.group}")
        if node.mode & STICKY:
            print("# flags: --t (sticky)")
        print(f"user::{self.rwx(node.mode >> 6)}")
        for (k, n), b in sorted(node.acl.items()):
            if k == "u":
                print(f"user:{n}:{self.rwx(b)}")
        print(f"group::{self.rwx(node.mode >> 3)}")
        for (k, n), b in sorted(node.acl.items()):
            if k == "g":
                print(f"group:{n}:{self.rwx(b)}")
        print(f"other::{self.rwx(node.mode)}")

    def parse_acl_spec(self, spec, with_perms):
        parts = spec.split(":")
        if len(parts) != (3 if with_perms else 2) or parts[0] not in ("u", "user", "g", "group"):
            raise FSError(f"entrada de ACL inválida: '{spec}' (ex.: u:ana:rw-, g:qa:r-x)")
        kind, name = parts[0][0], parts[1]
        if kind == "u" and name not in self.accounts:
            raise FSError(f"usuário inexistente: '{name}'")
        if kind == "g":
            self.need_group(name)
        if not with_perms:
            return kind, name, None
        if not re.fullmatch(r"[rwx-]{1,3}", parts[2]):
            raise FSError(f"permissões inválidas na ACL: '{parts[2]}'")
        return kind, name, sum(PERM_BIT[c] for c in set(parts[2]) if c in PERM_BIT)

    def cmd_setfacl(self, args):
        pos, opts = parse_opts(args, valued=("-m", "-x"), flags=("-b",))
        if not pos or not opts:
            raise FSError("uso: setfacl -m u:nome:rwx <caminho> | setfacl -x u:nome <caminho> | setfacl -b <caminho>")
        for p in pos:
            node = self.fs.resolve(p)
            self.require_owner(node, "alterar a ACL")
            if "-b" in opts:
                node.acl = {}
            if "-m" in opts:
                for spec in opts["-m"].split(","):
                    kind, name, bits = self.parse_acl_spec(spec, True)
                    node.acl[(kind, name)] = bits
            if "-x" in opts:
                for spec in opts["-x"].split(","):
                    kind, name, _ = self.parse_acl_spec(spec, False)
                    node.acl.pop((kind, name), None)
            self.log("SETFACL", f"{node.path}: {self.acl_text(node) or 'ACL removida'}")
            self.ok(f"ACL de {node.path}: {self.acl_text(node) or '(sem entradas estendidas)'}")

    def cmd_access_matrix(self, args):
        pos, opts = parse_opts(args, valued=("--users",))
        start = self.fs.resolve(pos[0] if pos else "/")
        self.require(start, "r" if start.is_dir else "")
        users = opts["--users"].split(",") if "--users" in opts else \
            [a.name for a in sorted(self.accounts.values(), key=lambda a: a.uid)]
        objs = [start] + ([n for n in self.fs.all_nodes() if self.fs._is_ancestor(start, n) and n is not start]
                          if start.is_dir else [])
        width = min(40, max(len(n.path) + (1 if n.is_dir else 0) for n in objs) + 2)
        print(self.s("[MATRIZ DE ACESSO] linhas = objetos | colunas = sujeitos | célula = direitos efetivos", "1"))
        print(f"{'Objeto':<{width}}{'Dono:Grupo':<16}" + "".join(f"{u:<9}" for u in users))
        for n in objs:
            label = n.path + ("/" if n.is_dir and n is not self.fs.root else "")
            row = f"{label[:width - 1]:<{width}}{(n.owner + ':' + n.group)[:15]:<16}"
            for u in users:
                row += f"{self.rwx(self.bits_for(n, u)[0]):<9}"
            print(row + (" +ACL" if n.acl else ""))

    def cmd_acl_trace(self, args):
        if not args or args[0] not in ("on", "off"):
            raise FSError("uso: acl_trace on|off")
        self.trace = args[0] == "on"
        self.ok(f"Rastreamento de verificações de ACL {'ativado' if self.trace else 'desativado'}")

    def cmd_io_log(self, args):
        if not args or args[0] not in ("on", "off"):
            raise FSError("uso: io_log on|off")
        self.storage.verbose = args[0] == "on"
        self.ok(f"Mensagens de E/S {'exibidas' if self.storage.verbose else 'ocultas'}")

    def cmd_exec(self, args):
        if not args:
            raise FSError("uso: exec <script>")
        node = self.fs.read(args[0])
        self.require(node, "rx")
        if getattr(node, "cipher", None) is not None:
            raise FSError(f"'{node.path}' está criptografado e não pode ser executado")
        if node.content is None:
            raise FSError(f"'{node.path}' não contém comandos (conteúdo simulado)")
        data = self.read_through(node, verbose=False)
        hit = find_signature(data)
        if hit:
            print(self.s("[ANTIVÍRUS - PROTEÇÃO EM TEMPO REAL]", "1"))
            print(self.s(f"[BLOQUEADO]: execução de '{node.path}' impedida: assinatura maliciosa "
                         f"'{hit[0]}' encontrada (offset {hit[1]}).", "31;1"))
            self.log("AV_BLOQUEIO", f"{node.path}: {hit[0]}", "ALERTA")
            return
        if self.exec_depth >= 4:
            raise FSError("profundidade máxima de execução aninhada atingida")
        cmds = [c.strip() for c in re.split(r"[;\n]", data.decode("utf-8", "replace")) if c.strip()]
        print(self.s(f"[EXEC] {node.path} como '{self.euser}' ({self.mode_name}): {len(cmds)} comando(s)", "2"))
        self.log("EXEC", node.path)
        self.exec_depth += 1
        try:
            for c in cmds:
                if c.split()[0].lower() in ("exit", "quit"):
                    return
                self.execute(c, echo=True)
        finally:
            self.exec_depth -= 1

    def cmd_encrypt_file(self, args):
        pos, opts = parse_opts(args, valued=("--key", "-k"))
        if len(pos) != 1:
            raise FSError("uso: encrypt_file <arquivo> --key <chave>")
        node = self.fs.read(pos[0])
        self.require(node, "rw")
        if getattr(node, "cipher", None) is not None:
            raise FSError(f"'{node.path}' já está criptografado")
        key = self.ask_secret(opts.get("--key", opts.get("-k")), "Chave: ")
        if len(key) < 4:
            raise FSError("chave muito curta (mínimo 4 caracteres)")
        plain = self.storage.file_bytes(node)
        blob = encrypt_blob(plain, key, b"S" if node.content is None else b"T")
        old_content = node.content
        node.cipher, node.content = blob, None
        try:
            self.fs._set_size(node, len(blob))
        except FSError:
            node.cipher, node.content = None, old_content
            raise
        self.forced.append(node)
        self.log("CRIPTOGRAFIA", f"{node.path} criptografado (a chave não é armazenada)")
        self.ok(f"Arquivo '{node.path}' criptografado com sucesso.")
        print(f"Conteúdo gravado nos blocos físicos: \"0x{blob[HEADER:HEADER + 8].hex().upper()}... "
              f"(Encrypted Ciphertext)\"")
        print(self.s(f"Cifra: fluxo SHA-256 (modo contador) + HMAC-SHA256 | chave derivada por PBKDF2 "
                     f"({KEY_ITERS} iterações, salt de 128 bits) | {len(plain)} B -> {len(blob)} B "
                     f"em {len(node.blocks)} bloco(s): [{self.blist(node.blocks)}]", "2"))

    def cmd_decrypt_file(self, args):
        pos, opts = parse_opts(args, valued=("--key", "-k"))
        if len(pos) != 1:
            raise FSError("uso: decrypt_file <arquivo> --key <chave>")
        node = self.fs.read(pos[0])
        self.require(node, "rw")
        if getattr(node, "cipher", None) is None:
            raise FSError(f"'{node.path}' não está criptografado")
        key = self.ask_secret(opts.get("--key", opts.get("-k")), "Chave: ")
        blob = self.read_through(node)
        try:
            flag, plain = decrypt_blob(blob, key)
        except CryptoError as e:
            self.log("DECIFRAR_FALHOU", f"{node.path}: {e}", "ALERTA")
            raise
        node.cipher = None
        node.content = None if flag == b"S" else plain.decode("utf-8", "replace")
        self.fs._set_size(node, len(plain))
        self.forced.append(node)
        self.log("DECIFRAR", f"{node.path} descriptografado")
        self.ok(f"Arquivo '{node.path}' descriptografado ({len(blob)} B cifrados -> {len(plain)} B) "
                f"e regravado em claro: [{self.blist(node.blocks)}]")

    def target_lba(self, pos, opts):
        if "--lba" in opts:
            try:
                lba = int(opts["--lba"])
            except ValueError:
                raise FSError("--lba deve ser inteiro")
            if not 0 <= lba < self.fs.nblocks:
                raise FSError(f"LBA fora do disco (0..{self.fs.nblocks - 1})")
            return lba, None
        if not pos:
            raise FSError("informe o arquivo alvo ou --lba N")
        node = self.fs.read(pos[0])
        if not node.blocks:
            raise FSError(f"'{node.path}' não possui blocos de dados")
        try:
            idx = int(opts.get("--block", 0))
            return node.blocks[idx], node
        except (ValueError, IndexError):
            raise FSError(f"--block deve estar entre 0 e {len(node.blocks) - 1}")

    def report_tamper(self, lba, d, off, what):
        print(self.s("[ATAQUE SIMULADO - ESCRITA DIRETA NO DISPOSITIVO DE BLOCOS]", "1;33"))
        print(f"{what} gravado no Disco {d + 1}, posição física {off} (LBA {self.storage.bnum(lba)}: "
              f"{self.storage.label(lba)})")
        print("O sistema de arquivos e o registro oficial de hashes NÃO foram informados da alteração.")

    def cmd_disk_tamper(self, args):
        pos, opts = parse_opts(args, valued=("--block", "--data", "--lba"))
        lba, _ = self.target_lba(pos, opts)
        data = opts.get("--data")
        d, off = self.storage.tamper(lba, data.encode("utf-8") if data is not None else None)
        self.report_tamper(lba, d, off, f"Texto \"{data}\"" if data is not None else "Ruído (16 bytes invertidos)")

    def cmd_inject_virus(self, args):
        pos, opts = parse_opts(args, valued=("--block", "--sig", "--lba"))
        name = opts.get("--sig", "EICAR-Test-File")
        if name not in SIGNATURES:
            raise FSError(f"assinatura desconhecida (use {', '.join(SIGNATURES)})")
        lba, _ = self.target_lba(pos, opts)
        d, off = self.storage.tamper(lba, SIGNATURES[name])
        self.report_tamper(lba, d, off, f"Código malicioso '{name}'")

    def scan_node(self, n):
        st = self.storage
        lbas = ([n.inode] if n.inode is not None else []) + list(n.blocks)
        bad = []
        for lba in lbas:
            for d, blob in st.physical_copies(lba):
                if sha256(blob) != st.hashes.get(lba):
                    bad.append((lba, d, st.hashes.get(lba, "?"), sha256(blob)))
        data = st.read_physical(n)
        hit = None if getattr(n, "cipher", None) is not None else find_signature(data)
        return bad, hit

    def cmd_antivirus_scan(self, args):
        pos, opts = parse_opts(args, flags=("--repair", "--quarantine", "-v"))
        fix = "--repair" in opts or "--quarantine" in opts
        if fix and not self.kernel:
            self.deny_privilege("antivirus_scan " + " ".join(args))
            return
        fs, st = self.fs, self.storage
        start = fs.resolve(pos[0] if pos else "/")
        self.require(start)
        files = [start] if not start.is_dir else [n for n in fs.files() if fs._is_ancestor(start, n)]
        print(self.s("[MÓDULO DE SEGURANÇA - VARREDURA DE INTEGRIDADE]", "1"))
        print(f"Analisando {len(files)} arquivos em busca de assinaturas maliciosas e hashes corrompidos...")
        width = max([len(n.path) for n in files] + [10]) + 2
        counts = {"ok": 0, "enc": 0, "alert": 0, "threat": 0, "isolated": 0}
        to_repair, to_quarantine = set(), []
        sys_bad = [(d, blob) for d, blob in st.physical_copies(0) if sha256(blob) != st.hashes.get(0)]
        if start is fs.root:
            tag = self.s("[ALERTA] metadados adulterados!", "31;1") if sys_bad else self.s("[OK - Íntegro]", "32")
            print(f"- {'(bloco 00: superbloco/raiz)':<{width}}: {tag}")
            if sys_bad:
                to_repair.add(0)
        for n in files:
            bad, hit = self.scan_node(n)
            enc = getattr(n, "cipher", None) is not None
            if not bad and not hit:
                key = "enc" if enc else "ok"
                counts[key] += 1
                label = "[OK - Criptografado e Íntegro]" if enc else "[OK - Íntegro]"
                print(f"- {n.path:<{width}}: {self.s(label, '32')}")
                continue
            if bad:
                counts["alert"] += 1
                blocks = sorted({b for b, _, _, _ in bad})
                kinds = ", ".join(("i-node " if b == n.inode else "bloco ") + st.bnum(b) for b in blocks)
                print(f"- {n.path:<{width}}: {self.s('[ALERTA] Hash do bloco difere do registro oficial!', '31;1')}")
                print(f"  Resultado: Possível modificação direta não autorizada no bloco do disco ({kinds}).")
                for b, d, want, got in bad[:3]:
                    print(self.s(f"  LBA {st.bnum(b)} (Disco {d + 1}) registro={want[:16]}... lido={got[:16]}...", "2"))
                if enc:
                    print("  Conteúdo criptografado: a verificação HMAC também falhará ao decifrar.")
                to_repair.update(blocks)
            if hit and not bad and self.in_quarantine(n):
                counts["isolated"] += 1
                print(f"- {n.path:<{width}}: {self.s(f'[ISOLADO] {hit[0]} (em quarentena, sem permissões)', '33')}")
                continue
            if hit:
                counts["threat"] += 1
                blk = n.blocks[hit[1] // fs.bs] if n.blocks else None
                print(f"{'' if bad else '- ' + n.path.ljust(width) + ': '}"
                      f"{'  ' if bad else ''}{self.s(f'[AMEAÇA] Assinatura maliciosa: {hit[0]}', '31;1')}"
                      + (f" (bloco {st.bnum(blk)}, offset {hit[1] % fs.bs})" if blk is not None else ""))
                to_quarantine.append(n)
        print(f"Resumo: {len(files)} arquivo(s) | {counts['ok']} íntegro(s) | {counts['enc']} criptografado(s) "
              f"íntegro(s) | {counts['alert']} com blocos adulterados | {counts['threat']} ameaça(s)"
              + (f" | {counts['isolated']} em quarentena" if counts["isolated"] else ""))
        level = "ALERTA" if counts["alert"] or counts["threat"] or sys_bad else "INFO"
        self.log("AV_SCAN", f"{start.path}: {counts['alert']} adulterado(s), {counts['threat']} ameaça(s)", level)
        if not fix and (to_repair or to_quarantine):
            print(self.s("Use 'antivirus_scan --repair --quarantine' (MODO_KERNEL) para corrigir.", "2"))
        if "--repair" in opts:
            for lba in sorted(to_repair):
                st.repair(lba)
                print(self.s(f"[REPARO] LBA {st.bnum(lba)} restaurado a partir do registro oficial "
                             f"({st.label(lba)})", "32"))
                self.log("AV_REPARO", f"LBA {lba}")
        if "--quarantine" in opts:
            for n in to_quarantine:
                if find_signature(st.read_physical(n)) is None:
                    print(self.s(f"[OK] {n.path}: assinatura eliminada pelo reparo do bloco", "32"))
                    continue
                self.quarantine(n)

    def in_quarantine(self, n):
        try:
            return self.fs._is_ancestor(self.fs.resolve("/quarentena"), n)
        except FSError:
            return False

    def quarantine(self, n):
        fs = self.fs
        try:
            qdir = fs.resolve("/quarentena")
        except FSError:
            qdir = self.sys_mkdir(fs, "/quarentena", mode=0o700)
        old = n.path
        name, i = n.name, 1
        while name in qdir.children:
            name, i = f"{n.name}.{i}", i + 1
        fs.move(old, f"/quarentena/{name}")
        n.owner, n.group, n.mode, n.acl = ROOT, ADMIN, 0, {}
        self.log("AV_QUARENTENA", f"{old} -> {n.path}", "ALERTA")
        print(self.s(f"[QUARENTENA] {old} -> {n.path} (dono root, permissões ---------, execução impedida)", "33"))

    def cmd_logs(self, args):
        _, opts = parse_opts(args, valued=("--tail", "-n", "--user"))
        rows = self.audit
        if "--user" in opts:
            rows = [r for r in rows if opts["--user"] in (r[1], r[2])]
        try:
            n = int(opts.get("--tail", opts.get("-n", 0)))
        except ValueError:
            raise FSError("--tail deve ser inteiro")
        if n:
            rows = rows[-n:]
        print(self.s(f"[LOG DE AUDITORIA] {len(self.audit)} evento(s) registrados", "1"))
        for t, user, euser, level, event, detail in rows:
            who = user + (f"->{euser}" if euser != user else "")
            line = f"{t:%H:%M:%S} [{level:<6}] {who:<14} {event:<15} {detail}"
            print(self.s(line, "31") if level == "ALERTA" else line)

    def cmd_demo3(self, args):
        root = self.accounts[ROOT]
        self.accounts = {ROOT: root}
        self.groups = {ADMIN: 0}
        self.next_uid = self.next_gid = 1000
        self.stack, self.elevated, self.sudo_ok = [ROOT], False, set()
        print("\n" + self.s(f"{' DEMONSTRAÇÃO ETAPA 3: SEGURANÇA E PROTEÇÃO ':=^78}", "1;35"))
        return self.run_lines(DEMOS3)


def main(argv=None):
    p = argparse.ArgumentParser(description="Simulador de Segurança e Proteção - Etapa 3")
    p.add_argument("script", nargs="?")
    p.add_argument("-s", "--strategy", default="indexada")
    p.add_argument("-b", "--block-size", default="4KB")
    p.add_argument("-n", "--blocks", type=int, default=64)
    p.add_argument("--fit", choices=["first", "best", "worst"], default="first")
    p.add_argument("--media", choices=["hdd", "ssd"], default="hdd")
    p.add_argument("--alg", default="sstf")
    p.add_argument("--cylinders", type=int, default=200)
    p.add_argument("--raid", choices=list(RAID_LEVELS), default="none")
    p.add_argument("--disks", type=int, default=3)
    p.add_argument("--root-password", default="root")
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
        fs = FileSystem(strategy, parse_size(a.block_size), a.blocks, a.fit)
        shell = SecShell(fs, not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ,
                         root_password=a.root_password, media=a.media, alg=get_alg(a.alg),
                         cylinders=a.cylinders, level=RAID_LEVELS[a.raid], ndisks=a.disks)
    except FSError as e:
        p.error(str(e))

    if a.demo:
        shell.execute("demo3")
    elif a.script:
        shell.execute(f"run {shlex.quote(a.script)}")
    else:
        shell.repl()


if __name__ == "__main__":
    main()
