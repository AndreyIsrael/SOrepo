# Simulador de Sistema de Arquivos — Etapa 1

Simulador em **Python 3** (arquivo único, sem dependências) de um sistema de arquivos com
hierarquia em árvore, operações CRUD e disco dividido em blocos de tamanho fixo.

## Como executar

```bash
python3 fs_sim.py                       # modo interativo (indexada, blocos de 4KB, 16 blocos)
python3 fs_sim.py -s contigua -b 1KB -n 64 --fit best
python3 fs_sim.py --demo                # roda as 3 demonstrações (indexada, contígua, encadeada)
python3 fs_sim.py --demo contigua       # só uma demonstração
python3 fs_sim.py comandos.txt          # executa um script de comandos
```

## Funcionalidades

| Requisito | Comandos |
|---|---|
| Árvore hierárquica, caminhos absolutos/relativos (`/`, `.`, `..`) | `tree`, `ls`, `cd`, `pwd` |
| **C**riar | `mkdir [-p]`, `create <arq> --size 10KB` / `--content "texto"` |
| **L**er | `cat`, `stat`, `ls` |
| **A**tualizar | `write`, `append`, `resize`, `mv` (mover/renomear) |
| **D**eletar | `rm [-r]`, `rmdir [-r]` |
| Blocos de tamanho fixo | `format --block-size 512B\|1KB\|4KB --blocks N` |
| Estratégias de alocação | `format --strategy contigua\|encadeada\|indexada` |
| Mapa do disco, fragmentação interna/externa, compactação | `fs_status [--details]`, `map`, `frag`, `fat`, `compact` |

### Estratégias de alocação

- **Contígua**: cada arquivo ocupa blocos consecutivos (first-, best- ou worst-fit).
  Quando um arquivo cresce, o simulador tenta estendê-lo no lugar e, se não der, o realoca.
  É a única estratégia com **fragmentação externa**: quando há espaço livre suficiente mas
  nenhuma lacuna contígua grande o bastante, a alocação falha e o relatório indica
  **Necessidade de Compactação: SIM**.
- **Encadeada (FAT)**: os blocos de um arquivo formam uma cadeia na tabela FAT (`fat` mostra a tabela).
- **Indexada (i-node)**: cada arquivo tem um bloco de i-node com os ponteiros
  para os blocos de dados (capacidade = tamanho do bloco / 4 bytes por ponteiro).

O bloco 00 é reservado: superbloco + diretório raiz (contígua/encadeada) ou i-node da raiz (indexada).

## Exemplo

```
> mkdir /sistema
> mkdir /sistema/logs
> create /sistema/logs/app.log --size 10KB
> tree
[ÁRVORE DO SISTEMA DE ARQUIVOS]
/
└── sistema/ [DIR]
    └── logs/ [DIR]
        └── app.log (10 KB) [ARQ]
> fs_status --details
```

# Etapa 2 — E/S, Escalonamento de Disco, SSD e RAID

O arquivo `io_sim.py` importa o `fs_sim.py` e coloca uma camada de armazenamento por baixo
do sistema de arquivos: toda gravação/leitura feita no shell vira requisições de E/S nos
blocos lógicos, que passam pelo RAID e chegam aos discos físicos (HDD ou SSD).

```bash
python3 io_sim.py                    # modo interativo (todos os comandos da etapa 1 continuam valendo)
python3 io_sim.py --demo             # demonstrações: sched, ssd e raid
python3 io_sim.py --demo raid
python3 io_sim.py --raid 5 --disks 3 --media hdd --alg sstf
```

| Requisito | Comandos |
|---|---|
| Integração com o sistema de arquivos | `write_file`, `read_file`, `cat`, `create`, `write`, `append`, `rm`... |
| Escalonamento do braço (FCFS, SSTF, SCAN, C-SCAN, LOOK, C-LOOK) | `sched`, `compare`, `head`, `pending`, `io_load`, `queue hold\|auto`, `flush` |
| SSD (páginas, FTL, coleta de lixo, TRIM, wear leveling) | `disk ssd`, `wear on\|off`, `ssd_status`, `ssd_stress` |
| RAID 0, 1, 4 e 5 com teste de falha e rebuild | `raid`, `raid_status`, `raid_fail`, `raid_test`, `raid_replace` |

```
> sched sstf 98 183 37 122 14 --head 53
[E/S] Requisições de leitura/escrita pendentes nas trilhas: [98, 183, 37, 122, 14]
Posição atual da cabeça de leitura: Trilha 53

--- ESCALONAMENTO DE DISCO: SSTF (Shortest Seek Time First) ---
Ordem de Atendimento : 53 -> 37 -> 14 -> 98 -> 122 -> 183
Deslocamento da Cabeça: |53-37| + |37-14| + |14-98| + |98-122| + |122-183|
Total de Movimento    : 16 + 23 + 84 + 24 + 61 = 208 trilhas
```

# Etapa 3 - Segurança e Proteção

O arquivo `sec_sim.py` importa o `io_sim.py` (que importa o `fs_sim.py`): todos os comandos das
etapas anteriores continuam valendo, agora sujeitos a autenticação, permissões e auditoria. Metadados
de segurança (dono, grupo, modo, ACL) são gravados nos i-nodes, e todo conteúdo passa pela camada de
E/S/RAID da etapa 2 até os blocos físicos.

```bash
python3 sec_sim.py                    # modo interativo (sessão inicial: root / senha "root")
python3 sec_sim.py --demo             # demonstração completa (exemplos 3.1 e 3.2)
python3 sec_sim.py --raid 5 --disks 3 --root-password minhaSenha
```

| Requisito | Comandos |
|---|---|
| Modo Usuário x Modo Kernel | `login`, `logout`, `su`, `sudo` (grupo `admin`), `whoami`, `mode`: `format`, `raid*`, `disk`, `useradd`, `chown`, `logs`... exigem `MODO_KERNEL` |
| Usuários, grupos e senhas com hash + salt | `useradd`, `userdel`, `groupadd`, `groupdel`, `usermod`, `passwd`, `users`, `groups`, `id`: PBKDF2-HMAC-SHA256 (100 000 iterações, salt de 128 bits) em `/etc/shadow` (600); conta bloqueada após 3 falhas |
| Permissões rwx (Proprietário/Grupo/Outros) + ACL | `ls -l`, `stat`, `chmod` (octal ou `u+x,g-w`), `chown`, `chgrp`, `getfacl`, `setfacl`, `access_matrix`, `acl_trace`, `exec`; sticky bit em `/tmp` (1777) |
| Formatar sem a estrutura padrão | `format ... --bare` (as demos das etapas 1 e 2 usam isso automaticamente) |
| Criptografia em repouso | `encrypt_file`, `decrypt_file`, `write_file ... --key`, `cat ... --key`: cifra de fluxo SHA-256 em modo contador + HMAC-SHA256, chave derivada por PBKDF2 |
| Integridade / antivírus | `antivirus_scan [--repair] [--quarantine]`, proteção em tempo real no `exec`; ataques simulados com `disk_tamper` e `inject_virus`; trilha de auditoria em `logs` |

Toda gravação legítima atualiza o registro oficial de hashes SHA-256 de cada bloco. `disk_tamper` e
`inject_virus` escrevem direto no disco físico, sem passar pelo sistema de arquivos, então a
varredura detecta a divergência de hash. Ela também procura assinaturas conhecidas (EICAR,
fork bomb, rootkit...). Com `--repair`, os blocos adulterados são regravados a partir do registro
oficial (a paridade do RAID é recalculada). Com `--quarantine`, os arquivos infectados vão para
`/quarentena` com permissão `000`.

```
> login --user carlos
Senha: **********
Autenticado com sucesso. Usuário: 'carlos' | Grupo: 'devs' | Modo: MODO_USUARIO

> read_file /sistema/config.sys
[SISTEMA DE SEGURANÇA - VERIFICAÇÃO DE ACL]
Objeto      : /sistema/config.sys
Proprietário: root (Grupo: admin)
Permissões  : rwxr-x--- (750)
Ação Pedida : LEITURA por 'carlos' (Grupo: devs)
Regra usada : Outros -> ---

[NEGADO]: O usuário 'carlos' não possui permissão de leitura no objeto '/sistema/config.sys'.
Tentativa não autorizada registrada nos logs do sistema.
```

# Etapa 4 - Gerência de Memória (Alocação Híbrida)

O arquivo `mem_sim.py` importa o `sec_sim.py` (que importa `io_sim.py` e `fs_sim.py`): todos os comandos
das etapas anteriores continuam valendo. A RAM física simulada é dividida em duas regiões:

- **Área Reservada** (padrão 4 MB, com o Núcleo Base do SO fixo nos primeiros 1 MB): processos críticos
  em alocação contígua, sem paginação, traduzidos por registradores Base/Limite (first/best/worst-fit).
- **RAM Dinâmica** (padrão 32 molduras de 4 KB): memória virtual com paginação por demanda para os
  processos comuns.

A memória secundária é o arquivo `/swap/pagefile.sys` (dono `root`, modo `600`) dentro do sistema de
arquivos da etapa 1. Todo swap-in/swap-out vira requisições de E/S nos blocos desse arquivo e passa pelo
RAID e pelo escalonamento de disco da etapa 2. Cada página gravada no swap tem um hash SHA-256: se o
bloco for adulterado direto no disco (`disk_tamper`, etapa 3), o swap-in detecta e encerra o processo.

```bash
python3 mem_sim.py                    # modo interativo (sessão inicial: root / senha "root")
python3 mem_sim.py --demo             # demonstração completa (exemplos 4.1 e 4.2)
python3 mem_sim.py --frames 16 --page-size 4KB --swap-slots 64 --replace segunda_chance
```

| Requisito | Comandos |
|---|---|
| Integração com as etapas anteriores | swap em `/swap/pagefile.sys` com E/S/RAID; `create_process --file` exige `r+x` no arquivo; processos têm dono; críticos, `memory_compact`, `mem_config` e troca de algoritmo exigem `MODO_KERNEL`; eventos vão para `logs` |
| Alocação híbrida | `create_process --name N --size 512KB --type critical` (Área Reservada) / `--type normal` (Memória Virtual), `terminate_process`, `ps`, `mem_config` |
| Tradução de endereços | `translate_address --process N --page P [--offset D]` ou `--address 0x...`; críticos usam Base/Limite |
| Page fault e substituição | `execute_step --process N --instruction "LOAD_DATA Página 2"` (`STORE_`/`WRITE_` ligam o bit M), `run_trace`, `page_table`, `replace_alg lru\|fifo\|segunda_chance`, `compare_alg` (inclui o Ótimo) |
| Fragmentação e compactação | `frag_report` (interna por página/moldura + externa na Área Reservada), `frag_report --every N` (relatório periódico), `memory_compact --reserved` |
| Análise de ocupação | `memory_status` (geral), `--reserved`, `--virtual`, `--frames`, `--swap` |

Na substituição, uma página com bit M=0 é descartada sem escrita (a cópia no swap já está atualizada);
com M=1 ela é gravada no swap antes de liberar a moldura.

```
> execute_step --process App_Navegador --instruction "LOAD_DATA Página 2"
[CPU - REFERÊNCIA DE MEMÓRIA EM EXECUÇÃO]
App_Navegador requisita acesso à Página Lógica 2...
- Consulta Tabela de Páginas -> Página Lógica 2 NÃO ESTÁ NA RAM!

[PAGE FAULT DETECTADO]: Página Lógica 2 ausente na RAM!
Memória RAM cheia. Executando Substituição de Página (Algoritmo LRU):
- Analisando histórico de acesso: Página Lógica 0 do PID 102 não é usada há 121ms (Mais antiga).
- Removendo Página Lógica 0 do PID 102 da RAM -> Salvando no Swap (Disco) [slot 4, bit M=1].
- Carregando Página Lógica 2 do App_Navegador na Moldura Física 0 (RAM Dinâmica) a partir do Swap (slot 9).
- Tabela de Páginas atualizada: Página Lógica 2 ---> Moldura Física 0.
```

# Etapa 5 - Processos, Threads e Escalonamento

O arquivo `proc_sim.py` importa o `mem_sim.py` (e, por ele, as etapas 1 a 3): todos os comandos anteriores
continuam valendo. Um `create_process` com `--burst` cria um processo escalonável. Ele ganha memória pela
etapa 4: tabela de páginas e swap (normal) ou bloco contíguo na Área Reservada (critical). O tempo é
simulado em ticks de 1 ms. A cada ms executado, a CPU faz uma referência a uma página do processo, passando
pela tradução, pelos page faults e pela substituição (LRU, FIFO ou Segunda Chance) da etapa 4.

Ciclo de vida: `NOVO -> PRONTO -> EXECUTANDO -> BLOQUEADO -> PRONTO -> ... -> CONCLUÍDO`.

- **Syscalls embutidas**: `--syscall "read_disk at 3ms (duration: 4ms)"`, em que `at` é o tempo de CPU do
  processo (thread T1) em que a instrução é atingida. Também existe `--syscall random` (evento aleatório com
  semente configurável). Várias syscalls podem ser separadas por `;`. `read_disk`/`write_disk` fazem E/S real
  no sistema de arquivos (etapas 1 e 2) com as permissões do dono do processo (etapa 3). Sem permissão, a
  syscall retorna `EACCES` e o processo não bloqueia.
- **Threads e mutex**: `--threads 2 --mutex Buffer_Video --cs 1:2`. O burst é dividido entre as threads, e
  cada uma pede o mutex após 1 ms de CPU e o mantém por 2 ms. Se o mutex estiver ocupado, a thread vai para
  BLOQUEADO e só volta a PRONTO quando o dono o libera (entrega direta ao primeiro da fila de espera).
  Processos diferentes podem disputar o mesmo mutex pelo nome.
- **Escalonamento**: filas por prioridade (0 = sistema/crítico, 1 = alta, 2 = baixa...), com Round-Robin e
  quantum dentro de cada nível e preempção quando chega um processo de prioridade maior. Também há `rr`,
  `priority` e `fcfs` para comparação.

```bash
python3 proc_sim.py                   # modo interativo (sessão inicial: root / senha "root")
python3 proc_sim.py --demo            # demonstração completa (exemplos 5.1 a 5.4)
python3 proc_sim.py --scheduler priority_rr --quantum 2ms --seed 42 --frames 32
```

| Requisito | Comandos |
|---|---|
| Integração com as etapas anteriores | memória paginada/reservada da etapa 4; syscalls de disco com E/S/RAID e permissões; dono do processo; `schedule`, `run_simulation` e `sched_config` exigem `MODO_KERNEL`; eventos em `logs` |
| Criação com perfil de E/S e ciclo de vida | `create_process --name N --burst 8ms --priority 1 [--type critical] [--arrival 0ms] [--syscall ...] [--threads N --mutex M --cs a:b] [--refs "0 1 W2"]`, `queues`, `terminate_process` |
| Referências a páginas e atualização da RAM | `run_simulation [--process N] --steps 3` (passo a passo + tabela das molduras), `schedule --trace` |
| Bloqueio automático (syscall e mutex) | mostrado em `run_simulation`/`schedule --trace` e na linha do tempo |
| Prioridade + Round-Robin | `schedule --algorithm Priority_RR --quantum 2ms [--reset] [--until T]`, `sched_config` |
| Métricas | `metrics` e o relatório do `schedule`: WT, TAT, tempo de resposta, tempo bloqueado, AWT/ATT/ART, trocas de contexto, utilização da CPU, vazão, preempções, syscalls, bloqueios por mutex, page faults; `compare_sched` compara os algoritmos com a mesma carga |

```
> schedule --algorithm Priority_RR --quantum 2ms --reset
--- LINHA DO TEMPO DA CPU ---
[ 0ms -  2ms] Executando PID 100   | Quantum 2ms expirou -> Volta p/ Fila P1
[ 2ms -  4ms] Executando PID 102   | Quantum 2ms expirou -> Volta p/ Fila P1
[ 4ms -  5ms] Executando PID 100   | Dispara Syscall read_disk -> Estado BLOQUEADO (até t=9ms)
[ 5ms]          PID 102: Dispara Syscall write_disk -> Estado BLOQUEADO (até t=6ms)
[ 5ms -  6ms] Executando PID 101/T1 | Preemptado por PID 102 (maior prioridade) -> Volta p/ Fila P2
[ 6ms]          Evento E/S: PID 102 encerra write_disk -> Estado BLOQUEADO -> PRONTO
[ 6ms -  8ms] Executando PID 102   | PID 102 CONCLUÍDO! (Fila P1 VAZIA)
```
