# Informativa sulla privacy di PhishLens

Ultimo aggiornamento: 2 ottobre 2026.

PhishLens è un'estensione di Chrome che controlla se le email sono
phishing. Questa pagina spiega quali dati tratta, dove vanno e cosa
viene conservato. Si applica all'estensione e al server ospitato,
PhishLens Cloud, all'indirizzo `anzouk.duckdns.org`.

## In breve

- PhishLens legge un'email solo quando lo chiedi (i pulsanti
  **Analizza**), oppure automaticamente se attivi **Analizza
  automaticamente le nuove email** nelle impostazioni (disattivato per
  impostazione predefinita).
- L'email viene inviata al server scelto nelle impostazioni: il tuo
  computer (Docker o Python in locale), il tuo server o PhishLens Cloud.
  L'estensione non invia nulla altrove.
- Il server analizza l'email e restituisce un verdetto. Non conserva il
  contenuto delle email, i mittenti né gli oggetti.
- La cronologia delle analisi resta nel tuo browser. Non viene mai
  caricata.
- Non ci sono account, strumenti di analisi, pubblicità né vendita di
  dati.

## Cosa legge l'estensione

Durante un'analisi, l'estensione legge dalla pagina di Gmail o Outlook
aperta:

- il testo del messaggio, l'oggetto e l'indirizzo del mittente;
- le destinazioni dei link nel messaggio;
- le indicazioni di autenticazione mostrate da Gmail (inviato da,
  firmato da);
- con **Leggi le intestazioni complete** attivo (impostazione
  predefinita), il messaggio originale così come lo fornisce la pagina
  «Mostra originale» di Gmail: tutte le intestazioni e le parti di
  testo, senza i file allegati;
- per l'analisi di un allegato, il file allegato.

La finestra dell'estensione legge anche i file che vi trascini e il
testo che incolli.

## Dove vanno i dati

Tutte le richieste di analisi vanno a un unico server, scelto nelle
impostazioni dell'estensione:

| Scelta | Dove va la tua email |
| --- | --- |
| Server locale | Il tuo computer (`127.0.0.1:8000`). Non ne esce nulla, a parte i controlli di threat intelligence indicati sotto. |
| URL personalizzato | Il server che hai inserito. Si applica l'informativa del suo proprietario. |
| PhishLens Cloud | Il server ospitato gestito dall'autore di PhishLens, su Oracle Cloud. Non viene conservato nulla (vedi sotto). |

Il server verifica i link trovati in un'email con servizi di threat
intelligence. Per farlo invia **solo gli indirizzi dei link** (mai il
testo dell'email, il mittente o l'oggetto):

- Google Safe Browsing (URL completi, quando è configurata una chiave
  API);
- URLhaus di abuse.ch (URL completi);
- Spamhaus DBL (nomi di dominio, tramite DNS);
- PhishTank (confronto con un elenco scaricato sul server; nessuna
  richiesta per email).

## Cosa viene conservato e per quanto tempo

| Dati | Dove | Per quanto tempo |
| --- | --- | --- |
| Cronologia delle analisi (oggetto, mittente, verdetto, punteggi, parole principali della spiegazione) | Il tuo browser (`chrome.storage.local`) | Finché non la cancelli (Statistiche, **Cancella**), al massimo le ultime 500 analisi |
| Cache delle spiegazioni | Il tuo browser | Finché l'estensione non viene rimossa |
| Risultati dell'analisi automatica (identificativo della conversazione, verdetto, punteggio) | Il tuo browser | Le ultime 500 email |
| Impostazioni | Il tuo browser | Finché non vengono modificate |
| Verdetti dei link (URL, verdetto, fonte) | Cache del server (SQLite) | 24 ore |
| Risultati restituiti (verdetto, punteggi, verdetti dei link, parole della spiegazione), indicizzati da un'impronta dell'email; non l'email stessa | Memoria del server | 24 ore, o fino al riavvio del server |
| Testo, intestazioni e allegati delle email | Memoria del server, durante la richiesta | Non conservati |
| Metadati delle richieste (ora, percorso, stato, indirizzo IP, browser) | Log dell'applicazione e del server web di PhishLens Cloud | 30 giorni; il contenuto delle richieste non viene mai registrato |

PhishLens Cloud conta anche i verdetti per modalità di calcolo, per il
monitoraggio (contatori Prometheus). Sono solo numeri, senza dati delle
email.

## Questo sito

`anzouk.duckdns.org` non imposta cookie e non usa script di
tracciamento, quindi non c'è nulla da accettare. Il numero di visite
proviene dai log del server web (pagina, ora, pagina di provenienza, tipo
di browser, indirizzo IP), letti con uno strumento ospitato in proprio;
sono conservati per 30 giorni e mai condivisi. La pagina chiede all'API
pubblica di GitHub il numero dell'ultima versione, che GitHub vede come
una normale richiesta del tuo browser.

## Autorizzazioni

| Autorizzazione | Perché |
| --- | --- |
| `storage` | Conservare le impostazioni, la cronologia delle analisi e le cache nel browser. |
| `notifications` | Avvisarti quando l'analisi automatica trova un'email di phishing. |
| `scripting` | Dopo un aggiornamento, inserire la nuova versione dei pulsanti di analisi nelle schede di Gmail e Outlook già aperte, così non devi ricaricarle. |
| Accesso a `mail.google.com` | Aggiungere i pulsanti di analisi e gli avvisi a Gmail e leggere l'email che analizzi. |
| Accesso a Outlook sul web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Lo stesso, in Outlook (solo analisi manuali). |
| Accesso a `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Inviare le analisi al server che hai scelto. |

## Le tue scelte

- Disattiva **Leggi le intestazioni complete** o **Analizza
  automaticamente le nuove email** nelle impostazioni in qualsiasi
  momento.
- Usa il server locale perché le email non lascino mai il tuo computer.
- Cancella la cronologia dalla vista Statistiche, oppure rimuovi
  l'estensione per eliminare tutto ciò che ha salvato.

## Minori

PhishLens non è rivolto ai minori e non raccoglie consapevolmente dati
che li riguardano.

## Modifiche e contatti

Le modifiche a questa informativa sono elencate nel
[registro delle modifiche](CHANGELOG.md) del progetto. Per domande,
apri una segnalazione su https://github.com/AnzouK/PhishLens/issues,
oppure segnala un problema di sicurezza in modo riservato come descritto
in [SECURITY.md](SECURITY.md).
