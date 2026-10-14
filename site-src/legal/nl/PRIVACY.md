# Privacybeleid van PhishLens

Laatst bijgewerkt: 2 oktober 2026.

PhishLens is een Chrome-extensie die e-mails op phishing controleert.
Deze pagina legt uit welke gegevens ze verwerkt, waar die naartoe gaan
en wat bewaard wordt. Ze geldt voor de extensie en voor de gehoste
server, PhishLens Cloud, op `anzouk.duckdns.org`.

## In het kort

- PhishLens leest een e-mail alleen als u daarom vraagt (de knoppen
  **Controleren**), of automatisch als u **Nieuwe e-mails automatisch
  controleren** aanzet in de instellingen (standaard uit).
- De e-mail wordt naar de in de instellingen gekozen server gestuurd: uw
  eigen computer (lokaal met Docker of Python), uw eigen server of
  PhishLens Cloud. De extensie stuurt niets ergens anders naartoe.
- De server controleert de e-mail en geeft een oordeel terug. Hij slaat
  geen e-mailinhoud, afzenders of onderwerpen op.
- Uw controlegeschiedenis blijft in uw browser. Ze wordt nooit geüpload.
- Er zijn geen accounts, geen analysetools, geen advertenties en geen
  verkoop van gegevens.

## Wat de extensie leest

Tijdens een controle leest de extensie van de geopende Gmail- of
Outlook-pagina:

- de tekst van het bericht, het onderwerp en het adres van de afzender;
- de bestemmingen van de links in het bericht;
- de authenticatiehints die Gmail toont (verzonden door, ondertekend
  door);
- met **Volledige headers lezen** aan (standaard) het originele bericht
  zoals de Gmail-pagina „Origineel weergeven” het levert: alle headers
  en de tekstdelen, zonder de bijgevoegde bestanden;
- bij de controle van een bijlage het bijgevoegde bestand.

Het venster van de extensie leest ook bestanden die u erin neerzet en
tekst die u plakt.

## Waar de gegevens naartoe gaan

Alle controleverzoeken gaan naar één server, gekozen in de instellingen
van de extensie:

| Keuze | Waar uw e-mail naartoe gaat |
| --- | --- |
| Lokale server | Uw eigen computer (`127.0.0.1:8000`). Er verlaat niets uw computer, behalve de hieronder genoemde controles bij dreigingsinformatie. |
| Eigen URL | De server die u hebt ingevoerd. Het beleid van de eigenaar geldt. |
| PhishLens Cloud | De gehoste server van de auteur van PhishLens, bij Oracle Cloud. Er wordt niets opgeslagen (zie hieronder). |

De server controleert de links in een e-mail bij diensten voor
dreigingsinformatie. Daarvoor stuurt hij **alleen de linkadressen**
(nooit de tekst van de e-mail, de afzender of het onderwerp):

- Google Safe Browsing (volledige URL's, als er een API-sleutel is
  ingesteld);
- URLhaus van abuse.ch (volledige URL's);
- Spamhaus DBL (domeinnamen, via DNS);
- PhishTank (vergeleken met een lijst die naar de server is gedownload;
  geen verzoek per e-mail).

## Wat bewaard wordt, en hoe lang

| Gegevens | Waar | Hoe lang |
| --- | --- | --- |
| Controlegeschiedenis (onderwerp, afzender, oordeel, scores, belangrijkste woorden van de uitleg) | Uw browser (`chrome.storage.local`) | Tot u ze wist (Statistieken, **Wissen**), hooguit de laatste 500 controles |
| Cache van uitleg | Uw browser | Tot de extensie wordt verwijderd |
| Resultaten van de automatische controle (gespreks-ID, oordeel, score) | Uw browser | De laatste 500 e-mails |
| Instellingen | Uw browser | Tot ze gewijzigd worden |
| Linkoordelen (URL, oordeel, bron) | Servercache (SQLite) | 24 uur |
| Teruggestuurde resultaten (oordeel, scores, linkoordelen, woorden van de uitleg), gekoppeld aan een hash van de e-mail; niet de e-mail zelf | Geheugen van de server | 24 uur, of tot de server herstart |
| Tekst, headers en bijlagen van e-mails | Geheugen van de server, tijdens het verzoek | Niet opgeslagen |
| Metagegevens van verzoeken (tijd, pad, status, IP-adres, browser) | Applicatie- en webserverlogs van PhishLens Cloud | 30 dagen; de inhoud van verzoeken wordt nooit gelogd |

PhishLens Cloud telt ook oordelen per beoordelingsroute voor monitoring
(Prometheus-tellers). Dat zijn alleen getallen, zonder e-mailgegevens.

## Deze website

`anzouk.duckdns.org` plaatst geen cookies en gebruikt geen
trackingscripts, dus er is niets om mee in te stemmen. Bezoekersaantallen
komen uit de logs van de eigen webserver (pagina, tijd, verwijzende
pagina, browsertype, IP-adres), gelezen met een zelf gehost hulpmiddel;
ze worden 30 dagen bewaard en nooit gedeeld. De pagina vraagt de
openbare API van GitHub om het nummer van de nieuwste versie, wat GitHub
ziet als een gewoon verzoek van uw browser.

## Rechten

| Recht | Waarom |
| --- | --- |
| `storage` | Uw instellingen, controlegeschiedenis en caches in de browser bewaren. |
| `notifications` | U waarschuwen als de automatische controle een phishingmail vindt. |
| `scripting` | Na een update de nieuwe versie van de controleknoppen in al geopende Gmail- en Outlook-tabbladen zetten, zodat u ze niet hoeft te vernieuwen. |
| Toegang tot `mail.google.com` | De controleknoppen en meldingen aan Gmail toevoegen en de e-mail lezen die u controleert. |
| Toegang tot Outlook op het web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Hetzelfde, in Outlook (alleen handmatige controles). |
| Toegang tot `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Controles naar de door u gekozen server sturen. |

## Uw keuzes

- Zet **Volledige headers lezen** of **Nieuwe e-mails automatisch
  controleren** op elk moment uit in de instellingen.
- Gebruik de lokale server, zodat e-mails uw computer nooit verlaten.
- Wis de geschiedenis in de weergave Statistieken, of verwijder de
  extensie om alles te wissen wat ze heeft opgeslagen.

## Kinderen

PhishLens is niet gericht op kinderen en verzamelt niet bewust gegevens
over hen.

## Wijzigingen en contact

Wijzigingen in dit beleid staan in het [wijzigingslogboek](CHANGELOG.md)
van het project. Voor vragen opent u een issue op
https://github.com/AnzouK/PhishLens/issues, of meldt u een
beveiligingsprobleem vertrouwelijk zoals beschreven in
[SECURITY.md](SECURITY.md).
