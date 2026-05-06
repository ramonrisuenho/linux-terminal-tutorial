# LinuxTerminal

Ambiente interativo no navegador para aprender os comandos básicos do Linux. Inclui um modo jogo CTF (Capture The Flag) com 10 desafios práticos.

![Status](https://img.shields.io/badge/status-online-00ff41)
![License](https://img.shields.io/badge/license-MIT-00cc33)
![No deps](https://img.shields.io/badge/dependencies-zero-004d14)

## Recursos

- Emulador de terminal com 30+ comandos Linux
- Sistema de arquivos virtual navegável
- **Modo Jogo CTF** — 10 missões forenses progressivas
- Histórico de comandos (setas ↑↓), autocomplete (Tab), atalhos (Ctrl+L, Ctrl+C)
- Pipes (`|`) e redirecionamento (`>`, `>>`) básicos
- Guia de referência interativo com tooltips
- Totalmente responsivo (desktop, tablet, smartphone)
- Zero dependências externas além de Google Fonts

## Hospedagem

Este projeto é estático e foi feito para rodar no **GitHub Pages**.

### Deploy

1. Suba os arquivos para um repositório
2. Em *Settings → Pages*, selecione a branch principal como source
3. Aguarde o GitHub publicar — geralmente em `https://USERNAME.github.io/REPO/`

### Cloudflare (opcional, recomendado)

Para usar Cloudflare como WAF/CDN na frente do GitHub Pages:

1. Adicione um domínio customizado no GitHub Pages (`Settings → Pages → Custom domain`)
2. Aponte os DNS do domínio para Cloudflare
3. Ative o *Proxy* (nuvem laranja) nos registros A/CNAME
4. Em **SSL/TLS**, use `Full` (não `Flexible`)
5. Em **Security → WAF**, configure regras conforme sua necessidade

A aplicação já inclui:
- `Content-Security-Policy` restritiva via `<meta>`
- `X-Content-Type-Options: nosniff`
- Sem `eval()`, sem `innerHTML` em conteúdo de usuário não escapado
- Sem cookies, sem `localStorage`, sem `fetch` externo

## Estrutura

```
.
├── index.html      # Estrutura
├── style.css       # Tema preto/verde + responsividade
├── terminal.js     # Lógica do emulador + CTF engine
├── 404.html        # Página de erro customizada
├── robots.txt      # SEO
├── sitemap.xml     # SEO
├── .nojekyll       # Desativa Jekyll no GitHub Pages
└── README.md       # Este arquivo
```

## Comandos disponíveis

### Navegação
`ls`, `cd`, `pwd`

### Arquivos
`mkdir`, `rm`, `cp`, `mv`, `touch`, `tar`

### Texto
`cat`, `grep`, `echo`, `head`, `tail`, `sort`, `wc`, `less`

### Permissões
`chmod`, `chown`

### Processos
`ps`, `kill`, `top`

### Sistema
`sudo`, `apt`, `df`, `du`, `free`, `env`, `whoami`, `uname`, `date`

### Rede
`ifconfig`, `ping`, `ssh`, `scp`, `wget`, `curl`

### Outros
`man`, `history`, `help`, `clear`, `exit`, `find`, `ctf`

## Modo CTF

Execute `ctf start` no terminal para iniciar a missão **Infiltração Sigma**:

| # | Flag | Pts | Comando |
|---|------|-----|---------|
| 1 | Copiar Relatório | 150 | `cp` |
| 2 | Mover Evidência | 150 | `mv` |
| 3 | Reconhecimento | 100 | `ls -a` |
| 4 | Permissões | 200 | `cat` |
| 5 | Processos | 200 | `ps aux` |
| 6 | Rede | 200 | `cat /etc/hosts` |
| 7 | Log Forense | 250 | `cat /var/log/...` |
| 8 | Arquivo Oculto | 250 | `ls -a` |
| 9 | Criptografia | 300 | `cat ~/cifra.txt` |
| 10 | Root Flag | 350 | `sudo cat` |

Subcomandos: `ctf start`, `ctf status`, `ctf hint`, `ctf reset`, `ctf stop`.

## Mobile

Em smartphones e tablets, o guia abre como drawer (toque no ícone de menu no canto superior esquerdo). Há também uma toolbar de teclas especiais (Tab, setas, Ctrl+L, Ctrl+C) acima do teclado virtual.

## Licença

MIT
