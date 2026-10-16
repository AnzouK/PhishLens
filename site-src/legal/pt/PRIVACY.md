# Política de privacidade do PhishLens

Última atualização: 16 de outubro de 2026.

O PhishLens é uma extensão do Chrome que verifica se os e-mails são
phishing. Esta página explica que dados trata, para onde vão e o que é
guardado. Aplica-se à extensão e ao servidor alojado, PhishLens Cloud, em
`phishlens.dev`.

## Em resumo

- O PhishLens lê um e-mail apenas quando o pede (os botões
  **Analisar**), ou automaticamente se ativar **Analisar novos e-mails
  automaticamente** nas definições (desligado por predefinição).
- O e-mail é enviado para o servidor escolhido nas definições: o seu
  próprio computador (Docker ou Python local), o seu próprio servidor ou
  o PhishLens Cloud. A extensão não envia nada para mais nenhum lado, exceto as comunicações que escolher enviar (ver abaixo).
- O servidor analisa o e-mail e devolve um veredito. Não guarda o
  conteúdo dos e-mails, os remetentes nem os assuntos.
- O seu histórico de análises fica no seu navegador. Nunca é enviado.
- Não há contas, medição de audiências, publicidade nem venda de dados.
- Pode comunicar um veredito errado ou partilhar as estatísticas das
  suas avaliações. Só é enviado o que vê e confirma: o texto do e-mail
  sem nomes, endereços, números nem caminhos de links, ou estatísticas
  sem qualquer conteúdo de e-mail.

## O que a extensão lê

Quando uma análise é executada, a extensão lê da página aberta do Gmail ou
do Outlook:

- o texto da mensagem, o assunto e o nome e endereço do remetente;
- os destinos dos links da mensagem;
- as indicações de autenticação que o Gmail mostra (enviado por,
  assinado por);
- com **Ler os cabeçalhos completos** ativo (predefinição), a mensagem
  original tal como a página «Mostrar original» do Gmail a fornece:
  todos os cabeçalhos e as partes de texto, sem os ficheiros anexos;
- numa análise de anexo, o ficheiro anexo.

A janela da extensão também lê os ficheiros que lá larga e o texto que
cola.

## Para onde vão os dados

Todos os pedidos de análise vão para um único servidor, escolhido nas
definições da extensão:

| Escolha | Para onde vai o seu e-mail |
| --- | --- |
| Servidor local | O seu próprio computador (`127.0.0.1:8000`). Nada sai dele, exceto as consultas de informação sobre ameaças indicadas abaixo. |
| URL personalizado | O servidor que introduziu. Aplica-se a política do respetivo proprietário. |
| PhishLens Cloud | O servidor alojado gerido pelo autor do PhishLens, no Oracle Cloud. Nada é guardado (ver abaixo). |

O servidor verifica os links encontrados num e-mail em serviços de
informação sobre ameaças. Para isso envia **apenas os endereços dos
links** (nunca o texto do e-mail, o remetente nem o assunto):

- Google Safe Browsing (URL completos, quando está configurada uma chave
  de API);
- URLhaus da abuse.ch (URL completos);
- Spamhaus DBL (nomes de domínio, por DNS);
- PhishTank (comparação com uma lista descarregada para o servidor;
  nenhum pedido por e-mail).

## As comunicações que escolhe enviar

Por baixo de cada veredito, o PhishLens mostra o idioma detetado e um
link **Veredito errado? Comunique-o**; a vista Estatísticas tem o mesmo
link para as análises marcadas como **Errado**, e um botão **Partilhar
as minhas estatísticas**. Nada é enviado antes de carregar em **Enviar**
depois de ler o que vai ser enviado.

| Comunicação | O que é enviado | O que nunca é enviado |
| --- | --- | --- |
| Veredito errado | O assunto, o texto e os domínios dos links desse e-mail após anonimização (nomes depois de uma saudação ou de um título, o seu próprio nome e endereço tal como aparecem na página do e-mail, endereços de e-mail, números de telefone, números longos como contas, cartões e códigos, IBAN, @nomes de utilizador, o caminho e os parâmetros de cada link), o texto tal como o editou, o veredito, as pontuações, o modo de cálculo, o idioma detetado e a sua resposta, a versão da extensão e o idioma da interface | O endereço do remetente, o e-mail original, os seus cabeçalhos e anexos |
| Estatísticas | Para cada análise do seu histórico: o dia, onde foi feita (Gmail, Outlook, janela da extensão), o veredito, as pontuações, se o remetente era de confiança, a sua avaliação Certo / Errado, o idioma detetado e a sua resposta | Assuntos, remetentes, textos, links |

As comunicações vão para o PhishLens Cloud, seja qual for o servidor que
usa para as análises. O servidor anonimiza o texto uma segunda vez com as
mesmas regras, guarda a comunicação sem o seu endereço IP nem outros
dados do pedido (o registo do servidor web descrito abaixo continua a
registar o pedido durante 30 dias) e devolve uma referência. As
comunicações servem apenas para medir e melhorar o PhishLens (por
exemplo, para treinar o modelo de texto com e-mails legítimos que avaliou
mal); nunca são publicadas nem partilhadas. São guardadas no máximo dois
anos. Para apagar uma comunicação, abra um pedido em
https://github.com/AnzouK/PhishLens/issues com a respetiva referência (a
referência por si só não revela nada da comunicação).

Para permitir comunicar a partir da vista Estatísticas, o texto
anonimizado das suas últimas análises no Gmail e no Outlook fica no seu
navegador durante 7 dias (no máximo 50 e-mails). Nunca sai do navegador,
a menos que comunique essa análise.

## O que é guardado, e durante quanto tempo

| Dados | Onde | Durante quanto tempo |
| --- | --- | --- |
| Histórico de análises (assunto, remetente, veredito, pontuações, principais palavras da explicação, idioma detetado e a sua resposta) | O seu navegador (`chrome.storage.local`) | Até o limpar (Estatísticas, **Limpar**), no máximo as últimas 500 análises |
| Cache das explicações | O seu navegador | Até a extensão ser removida |
| Texto anonimizado das análises recentes no Gmail e no Outlook, para comunicações | O seu navegador | 7 dias, no máximo 50 e-mails; apagado com o histórico |
| Comunicações que enviou (texto anonimizado ou estatísticas, ver acima) | PhishLens Cloud | No máximo dois anos; apagadas a pedido com a referência |
| Resultados da análise automática (identificador da conversa, veredito, pontuação) | O seu navegador | Os últimos 500 e-mails |
| Definições | O seu navegador | Até serem alteradas |
| Vereditos dos links (URL, veredito, fonte) | Cache do servidor (SQLite) | 24 horas |
| Resultados devolvidos (veredito, pontuações, vereditos dos links, palavras da explicação), indexados por uma impressão digital do e-mail; não o próprio e-mail | Memória do servidor | 24 horas, ou até o servidor reiniciar |
| Texto, cabeçalhos e anexos dos e-mails | Memória do servidor, durante o pedido | Não são guardados |
| Metadados dos pedidos (hora, caminho, estado, endereço IP, navegador) | Registos da aplicação e do servidor web do PhishLens Cloud | 30 dias; o conteúdo dos pedidos nunca é registado |

O PhishLens Cloud também conta os vereditos por modo de cálculo, para
monitorização (contadores Prometheus). São apenas números, sem dados de
e-mails.

## Este site

`phishlens.dev` não coloca cookies nem usa scripts de rastreio, por
isso não há nada a aceitar. A contagem de visitas vem dos registos do
próprio servidor web (página, hora, página de origem, tipo de navegador,
endereço IP), lidos com uma ferramenta alojada pelo próprio; são
guardados durante 30 dias e nunca partilhados. A página pede à API
pública do GitHub o número da versão mais recente, que o GitHub vê como
um pedido normal do seu navegador.

## Permissões

| Permissão | Porquê |
| --- | --- |
| `storage` | Guardar as suas definições, o histórico de análises e as caches no navegador. |
| `notifications` | Avisá-lo quando a análise automática encontra um e-mail de phishing. |
| `scripting` | Após uma atualização, colocar a nova versão dos botões de análise nos separadores do Gmail e do Outlook já abertos, para que não tenha de os atualizar. |
| Acesso a `mail.google.com` | Acrescentar os botões de análise e as faixas ao Gmail e ler o e-mail que analisa. |
| Acesso ao Outlook na web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | O mesmo, no Outlook (apenas análises manuais). |
| Acesso a `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Enviar as análises para o servidor que escolheu. |

## As suas opções

- Desligue **Ler os cabeçalhos completos** ou **Analisar novos e-mails
  automaticamente** nas definições a qualquer momento.
- Use o servidor local para que os e-mails nunca saiam do seu
  computador.
- Limpe o histórico na vista Estatísticas, ou remova a extensão para
  apagar tudo o que guardou.
- Se nunca enviar uma comunicação, nada sai do seu navegador além das
  próprias análises, para o servidor que escolheu.

## Crianças

O PhishLens não se destina a crianças e não recolhe conscientemente
dados sobre elas.

## Alterações e contacto

As alterações a esta política estão listadas no
[registo de alterações](CHANGELOG.md) do projeto. Para questões, abra
um pedido em https://github.com/AnzouK/PhishLens/issues, ou comunique um
problema de segurança de forma confidencial como descrito em
[SECURITY.md](SECURITY.md).
