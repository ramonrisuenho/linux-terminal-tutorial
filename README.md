# LinuxTerminal

Um terminal Linux interativo feito com HTML, CSS e JavaScript puro para ensinar comandos usados em ambientes reais. O projeto simula um shell no navegador, com sistema de arquivos virtual, guia lateral de referência e um modo CTF progressivo para praticar investigação, navegação, leitura de arquivos, processos, rede e permissões.

[![Status](https://img.shields.io/badge/status-online-00ff41)](#)
[![License](https://img.shields.io/badge/license-MIT-00cc33)](#licença)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-004d14)](#tecnologias)


## Visão Geral

O LinuxTerminal foi criado para funcionar como um ambiente seguro de aprendizado. Em vez de apenas listar comandos, ele permite que a pessoa pratique em um terminal simulado, explore diretórios, leia arquivos, use pipes, redirecione saídas e avance por desafios estilo Capture The Flag.

Tudo roda no navegador. Não há backend, banco de dados, cookies, autenticação ou dependências externas além da fonte carregada pelo Google Fonts.

## Recursos

- Emulador de terminal com 50 comandos Linux.
- Sistema de arquivos virtual navegável.
- Guia lateral interativo com comandos por categoria.
- Exemplos clicáveis para inserir comandos no terminal.
- Modo CTF com 10 missões sequenciais.
- Flag bônus ao final do CTF, com tentativa única e animação especial.
- HUD de pontuação, flags capturadas e dicas.
- Histórico de comandos com setas para cima e baixo.
- Autocomplete com Tab.
- Atalhos como `Ctrl+L` e `Ctrl+C`.
- Suporte básico a pipes (`|`) e redirecionamento (`>`, `>>`).
- Layout responsivo para desktop, tablet e smartphone.
- Links sociais integrados ao cabeçalho lateral.

## Tecnologias

- HTML5
- CSS3
- JavaScript puro
- GitHub Pages
- Sem frameworks
- Sem build step
- Sem dependências de runtime

## Como Usar

Abra o projeto no navegador e digite comandos diretamente no terminal.

Alguns exemplos:

```bash
help
ls
cd /home/usuario
cat readme.txt
find / -name "*.txt"
ps aux
ctf start
```

Também é possível clicar em comandos no menu lateral para inserir exemplos automaticamente.

## Comandos Disponíveis

### Navegação

`ls`, `cd`, `pwd`

### Arquivos

`mkdir`, `rm`, `cp`, `mv`, `touch`, `file`, `tar`

### Texto

`cat`, `grep`, `echo`, `head`, `tail`, `sort`, `wc`, `less`

### Busca

`find`, `which`

### Permissões

`chmod`, `chown`

### Processos

`ps`, `kill`, `top`

### Sistema

`sudo`, `apt`, `df`, `du`, `free`, `env`, `whoami`, `id`, `hostname`, `uptime`, `uname`, `date`

### Rede

`ifconfig`, `ip`, `ping`, `ssh`, `scp`, `wget`, `curl`

### Ajuda e Terminal

`man`, `history`, `help`, `clear`, `exit`, `ctf`

## Modo CTF

Execute o comando abaixo para iniciar a missão:

```bash
ctf start
```

O CTF segue uma ordem sequencial. Cada flag depende do uso correto do comando esperado para aquela etapa, simulando um fluxo de investigação em um ambiente Linux.

| # | Missão | Pontos | Comando principal |
|---|--------|--------|-------------------|
| 1 | Copiar relatório | 150 | `cp` |
| 2 | Mover evidência | 150 | `mv` |
| 3 | Reconhecimento | 100 | `ls -a` |
| 4 | Permissões | 200 | `cat` |
| 5 | Processos | 200 | `ps aux` |
| 6 | Rede | 200 | `cat /etc/hosts` |
| 7 | Log forense | 250 | `cat /var/log/...` |
| 8 | Arquivo oculto | 250 | `ls -a` |
| 9 | Criptografia | 300 | `cat ~/cifra.txt` |
| 10 | Root flag | 350 | `sudo cat` |

Subcomandos disponíveis:

```bash
ctf start
ctf status
ctf hint
ctf reset
ctf stop
```

Ao concluir as 10 flags principais, o jogador pode tentar uma flag bônus. Essa tentativa é única: depois de enviar, o valor digitado é cifrado no campo, com animação individual nas letras. Se a flag estiver correta, o usuário recebe 500 pontos adicionais e uma animação especial de conclusão avançada.

## Estrutura do Projeto

```text
.
|-- index.html        # Estrutura principal da aplicação
|-- style.css         # Tema visual, responsividade e animações
|-- terminal.js       # Emulador, comandos, filesystem virtual e CTF
|-- 404.html          # Página de erro customizada
|-- robots.txt        # Configuração para crawlers
|-- sitemap.xml       # Sitemap para SEO
|-- .nojekyll         # Desativa o Jekyll no GitHub Pages
|-- _headers.example  # Exemplo de headers para hospedagens compatíveis
`-- README.md         # Documentação do projeto
```

## Segurança

O projeto foi pensado para ser simples de hospedar e reduzir superfície de ataque:

- Aplicação totalmente estática.
- Sem backend.
- Sem cookies.
- Sem `localStorage`.
- Sem chamadas `fetch` externas para lógica da aplicação.
- Sem `eval()`.
- Conteúdos digitados pelo usuário são tratados antes de serem exibidos no terminal.
- Inclui política CSP via `<meta>`.
- Inclui arquivo `_headers.example` para plataformas que suportam headers customizados.

## Licença

MIT
