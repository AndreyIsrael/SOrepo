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
