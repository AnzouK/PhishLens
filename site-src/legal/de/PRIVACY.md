# Datenschutzerklärung von PhishLens

Zuletzt aktualisiert: 2. Oktober 2026.

PhishLens ist eine Chrome-Erweiterung, die E-Mails auf Phishing prüft.
Diese Seite erklärt, welche Daten sie verarbeitet, wohin diese gehen und
was gespeichert wird. Sie gilt für die Erweiterung und den gehosteten
Server PhishLens Cloud unter `anzouk.duckdns.org`.

## Kurz gesagt

- PhishLens liest eine E-Mail nur, wenn Sie darum bitten (die
  Schaltflächen **Prüfen**), oder automatisch, wenn Sie in den
  Einstellungen **Neue E-Mails automatisch prüfen** einschalten
  (standardmäßig aus).
- Die E-Mail wird an den in den Einstellungen gewählten Server gesendet:
  Ihren eigenen Computer (lokal mit Docker oder Python), Ihren eigenen
  Server oder PhishLens Cloud. Die Erweiterung sendet nichts anderswohin.
- Der Server prüft die E-Mail und gibt ein Urteil zurück. Er speichert
  weder E-Mail-Inhalte noch Absender oder Betreffzeilen.
- Ihr Prüfverlauf bleibt in Ihrem Browser. Er wird nie hochgeladen.
- Es gibt keine Konten, keine Analyse-Tools, keine Werbung und keinen
  Verkauf von Daten.

## Was die Erweiterung liest

Bei einer Prüfung liest die Erweiterung aus der geöffneten Gmail- oder
Outlook-Seite:

- den Text der Nachricht, ihren Betreff und die Adresse des Absenders;
- die Ziele der Links in der Nachricht;
- die Authentifizierungshinweise, die Gmail anzeigt (gesendet von,
  signiert von);
- bei eingeschaltetem **Vollständige Header lesen** (Standard) die
  Originalnachricht, wie sie die Gmail-Seite „Original anzeigen“
  liefert: alle Header und die Textteile, ohne die angehängten Dateien;
- bei der Prüfung eines Anhangs die angehängte Datei.

Das Fenster der Erweiterung liest außerdem Dateien, die Sie dort
ablegen, und Text, den Sie einfügen.

## Wohin die Daten gehen

Alle Prüfanfragen gehen an einen einzigen Server, den Sie in den
Einstellungen der Erweiterung wählen:

| Auswahl | Wohin Ihre E-Mail geht |
| --- | --- |
| Lokaler Server | Ihr eigener Computer (`127.0.0.1:8000`). Nichts verlässt ihn, außer den unten genannten Abfragen von Bedrohungsdaten. |
| Eigene URL | Der Server, den Sie eingegeben haben. Es gilt die Richtlinie seines Betreibers. |
| PhishLens Cloud | Der gehostete Server des PhishLens-Autors bei Oracle Cloud. Nichts wird gespeichert (siehe unten). |

Der Server prüft die in einer E-Mail gefundenen Links bei Diensten für
Bedrohungsdaten. Dazu sendet er **nur die Linkadressen** (nie den
E-Mail-Text, den Absender oder den Betreff):

- Google Safe Browsing (vollständige URLs, wenn ein API-Schlüssel
  eingerichtet ist);
- URLhaus von abuse.ch (vollständige URLs);
- Spamhaus DBL (Domainnamen, über DNS);
- PhishTank (Abgleich mit einer auf den Server heruntergeladenen Liste;
  keine Anfrage pro E-Mail).

## Was gespeichert wird und wie lange

| Daten | Wo | Wie lange |
| --- | --- | --- |
| Prüfverlauf (Betreff, Absender, Urteil, Werte, wichtigste Wörter der Erklärung) | Ihr Browser (`chrome.storage.local`) | Bis Sie ihn löschen (Statistiken, **Löschen**), höchstens die letzten 500 Prüfungen |
| Zwischenspeicher der Erklärungen | Ihr Browser | Bis die Erweiterung entfernt wird |
| Ergebnisse der automatischen Prüfung (Unterhaltungs-ID, Urteil, Wert) | Ihr Browser | Die letzten 500 E-Mails |
| Einstellungen | Ihr Browser | Bis zur Änderung |
| Link-Urteile (URL, Urteil, Quelle) | Server-Cache (SQLite) | 24 Stunden |
| Zurückgesendete Ergebnisse (Urteil, Werte, Link-Urteile, Wörter der Erklärung), über einen Hash der E-Mail zugeordnet; nicht die E-Mail selbst | Arbeitsspeicher des Servers | 24 Stunden oder bis zum Neustart des Servers |
| Text, Header und Anhänge von E-Mails | Arbeitsspeicher des Servers, während der Anfrage | Nicht gespeichert |
| Metadaten der Anfragen (Zeit, Pfad, Status, IP-Adresse, Browser) | Anwendungs- und Webserver-Protokolle von PhishLens Cloud | 30 Tage; der Inhalt von Anfragen wird nie protokolliert |

PhishLens Cloud zählt außerdem Urteile pro Bewertungsweg für die
Überwachung (Prometheus-Zähler). Das sind nur Zahlen, ohne E-Mail-Daten.

## Diese Website

`anzouk.duckdns.org` setzt keine Cookies und verwendet keine
Tracking-Skripte, daher gibt es nichts zuzustimmen. Besucherzahlen
stammen aus den Protokollen des eigenen Webservers (Seite, Zeit,
verweisende Seite, Browsertyp, IP-Adresse) und werden mit einem selbst
betriebenen Werkzeug ausgewertet; sie werden 30 Tage aufbewahrt und nie
weitergegeben. Die Seite fragt die öffentliche API von GitHub nach der
neuesten Versionsnummer, was GitHub als normale Anfrage Ihres Browsers
sieht.

## Berechtigungen

| Berechtigung | Wozu |
| --- | --- |
| `storage` | Ihre Einstellungen, Ihren Prüfverlauf und die Zwischenspeicher im Browser aufbewahren. |
| `notifications` | Sie warnen, wenn die automatische Prüfung eine Phishing-E-Mail findet. |
| `scripting` | Nach einem Update die neue Version der Prüf-Schaltflächen in bereits geöffnete Gmail- und Outlook-Tabs einsetzen, damit Sie diese nicht neu laden müssen. |
| Zugriff auf `mail.google.com` | Die Prüf-Schaltflächen und Hinweise in Gmail anzeigen und die geprüfte E-Mail lesen. |
| Zugriff auf Outlook im Web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Dasselbe in Outlook (nur manuelle Prüfungen). |
| Zugriff auf `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Prüfungen an den von Ihnen gewählten Server senden. |

## Ihre Möglichkeiten

- Schalten Sie **Vollständige Header lesen** oder **Neue E-Mails
  automatisch prüfen** jederzeit in den Einstellungen aus.
- Verwenden Sie den lokalen Server, damit E-Mails Ihren Computer nie
  verlassen.
- Löschen Sie den Verlauf in der Ansicht Statistiken, oder entfernen Sie
  die Erweiterung, um alles zu löschen, was sie gespeichert hat.

## Kinder

PhishLens richtet sich nicht an Kinder und erhebt nicht wissentlich
Daten über sie.

## Änderungen und Kontakt

Änderungen dieser Erklärung sind im [Änderungsprotokoll](CHANGELOG.md)
des Projekts aufgeführt. Bei Fragen eröffnen Sie ein Issue unter
https://github.com/AnzouK/PhishLens/issues oder melden Sie ein
Sicherheitsproblem vertraulich wie in [SECURITY.md](SECURITY.md)
beschrieben.
