# Informativa sulla privacy di PhishLens

Ultimo aggiornamento: 27 ottobre 2026.

PhishLens è un'estensione di Chrome che controlla se le email sono
phishing. Questa pagina spiega quali dati tratta, dove vanno e cosa
viene conservato. Si applica all'estensione e al server ospitato,
PhishLens Cloud, all'indirizzo `phishlens.dev`.

## In breve

- PhishLens legge un'email solo quando lo chiedi (i pulsanti
  **Analizza**), oppure automaticamente se attivi **Analizza
  automaticamente le nuove email** nelle impostazioni (disattivato per
  impostazione predefinita).
- L'email viene inviata al server scelto nelle impostazioni: il tuo
  computer (Docker o Python in locale), il tuo server o PhishLens Cloud.
  L'estensione non invia nulla altrove, salvo le segnalazioni che scegli di inviare (vedi sotto).
- Il server analizza l'email e restituisce un verdetto. Non conserva il
  contenuto delle email, i mittenti né gli oggetti.
- La cronologia delle analisi resta nel tuo browser. Non viene mai
  caricata.
- Non ci sono account, strumenti di analisi, pubblicità né vendita di
  dati.
- Puoi segnalare un verdetto sbagliato o condividere le statistiche
  delle tue valutazioni. Viene inviato solo ciò che vedi e confermi: il
  testo dell'email senza nomi, indirizzi, numeri né percorsi dei link,
  oppure statistiche senza alcun contenuto delle email.

## Cosa legge l'estensione

Durante un'analisi, l'estensione legge dalla pagina di Gmail o Outlook
aperta:

- il testo del messaggio, l'oggetto, il nome e l'indirizzo del mittente;
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

## Le segnalazioni che scegli di inviare

Sotto ogni verdetto PhishLens mostra la lingua rilevata e un link
**Verdetto sbagliato? Segnalalo**; la vista Statistiche ha lo stesso link
per le analisi segnate come **Sbagliato**, e un pulsante **Condividi le
mie statistiche**. Nulla viene inviato finché non premi **Invia** dopo
aver letto cosa verrà inviato.

| Segnalazione | Cosa viene inviato | Cosa non viene mai inviato |
| --- | --- | --- |
| Verdetto sbagliato | L'oggetto, il testo e i domini dei link di quell'email dopo l'anonimizzazione (nomi dopo un saluto o un titolo, il tuo nome e il tuo indirizzo come appaiono nella pagina della posta, indirizzi email, numeri di telefono, numeri lunghi come conti, carte e codici, IBAN, @nomi utente, il percorso e i parametri di ogni link), il testo come l'hai modificato, il verdetto, i punteggi, la modalità di calcolo, la lingua rilevata e la tua risposta, la versione dell'estensione e la lingua dell'interfaccia | L'indirizzo del mittente, l'email originale, le sue intestazioni e i suoi allegati |
| Statistiche | Per ogni analisi della tua cronologia: il giorno, dove è stata fatta (Gmail, Outlook, finestra dell'estensione), il verdetto, i punteggi, se il mittente era attendibile, la tua valutazione Giusto / Sbagliato, la lingua rilevata e la tua risposta | Oggetti, mittenti, testi, link |

Le segnalazioni vanno a PhishLens Cloud, qualunque server tu usi per le
analisi. Il server anonimizza il testo una seconda volta con le stesse
regole, salva la segnalazione senza il tuo indirizzo IP né altri dati
della richiesta (il log del server web descritto più sotto registra
comunque la richiesta per 30 giorni) e restituisce un riferimento. Le
segnalazioni servono solo a misurare e migliorare PhishLens (per esempio
ad addestrare il modello del testo su email legittime giudicate male);
non vengono mai pubblicate né condivise. Sono conservate al massimo due
anni. Per far cancellare una segnalazione, scrivi a
privacy@phishlens.dev indicando il suo riferimento, oppure apri una
segnalazione su https://github.com/AnzouK/PhishLens/issues (il
riferimento da solo non rivela nulla della segnalazione).

Per permettere di segnalare dalla vista Statistiche, il testo
anonimizzato delle tue ultime analisi di Gmail e Outlook resta nel tuo
browser per 7 giorni (al massimo 50 email). Non lascia mai il browser,
a meno che tu non segnali quell'analisi.

## Cosa viene conservato e per quanto tempo

| Dati | Dove | Per quanto tempo |
| --- | --- | --- |
| Cronologia delle analisi (oggetto, mittente, verdetto, punteggi, parole principali della spiegazione, lingua rilevata e la tua risposta) | Il tuo browser (`chrome.storage.local`) | Finché non la cancelli (Statistiche, **Cancella**), al massimo le ultime 500 analisi |
| Cache delle spiegazioni | Il tuo browser | Finché l'estensione non viene rimossa |
| Testo anonimizzato delle analisi recenti di Gmail e Outlook, per le segnalazioni | Il tuo browser | 7 giorni, al massimo 50 email; cancellato con la cronologia |
| Segnalazioni che hai inviato (testo anonimizzato o statistiche, vedi sopra) | PhishLens Cloud | Al massimo due anni; cancellate su richiesta con il riferimento |
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

`phishlens.dev` non imposta cookie e non usa script di
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
| Accesso a `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Inviare le analisi al server che hai scelto. |

## Le tue scelte

- Disattiva **Leggi le intestazioni complete** o **Analizza
  automaticamente le nuove email** nelle impostazioni in qualsiasi
  momento.
- Usa il server locale perché le email non lascino mai il tuo computer.
- Cancella la cronologia dalla vista Statistiche, oppure rimuovi
  l'estensione per eliminare tutto ciò che ha salvato.
- Se non invii mai una segnalazione, nulla lascia il tuo browser oltre
  alle analisi stesse, verso il server che hai scelto.

## Minori

PhishLens non è rivolto ai minori e non raccoglie consapevolmente dati
che li riguardano.

## Chi è responsabile

PhishLens è un progetto personale e non commerciale, gestito da un
privato, responsabile di PhishLens Cloud e di questo sito. PhishLens
Cloud funziona su Oracle Cloud Infrastructure (Oracle Corporation,
Austin, Texas, Stati Uniti), nel suo data center di Francoforte, in
Germania. Il DNS del dominio passa da Cloudflare (Cloudflare, Inc., San
Francisco, California, Stati Uniti). Contatto: privacy@phishlens.dev.

## I tuoi diritti

Puoi chiedere che cosa PhishLens Cloud conserva su di te e farlo
cancellare: una segnalazione che hai inviato (indica il suo
riferimento), oppure le righe del registro del server web relative alle
tue richieste, conservate 30 giorni (indica la data e il tuo indirizzo
IP). Scrivi a privacy@phishlens.dev; riceverai una risposta entro 30
giorni. PhishLens non conserva email, account né profili, quindi di
solito non c'è altro da restituire o cancellare.

## Modifiche e contatti

Le modifiche a questa informativa sono elencate nel [registro delle
modifiche](CHANGELOG.md) del progetto. Domande e richieste sui tuoi
dati: privacy@phishlens.dev. Errori e suggerimenti: apri una
segnalazione su https://github.com/AnzouK/PhishLens/issues. Problemi di
sicurezza: segnalali in modo riservato come descritto in
[SECURITY.md](SECURITY.md).
