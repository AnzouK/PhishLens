# Privacybeleid van PhishLens

Laatst bijgewerkt: 16 oktober 2026.

PhishLens is een Chrome-extensie die e-mails op phishing controleert.
Deze pagina legt uit welke gegevens ze verwerkt, waar die naartoe gaan
en wat bewaard wordt. Ze geldt voor de extensie en voor de gehoste
server, PhishLens Cloud, op `phishlens.dev`.

## In het kort

- PhishLens leest een e-mail alleen als u daarom vraagt (de knoppen
  **Controleren**), of automatisch als u **Nieuwe e-mails automatisch
  controleren** aanzet in de instellingen (standaard uit).
- De e-mail wordt naar de in de instellingen gekozen server gestuurd: uw
  eigen computer (lokaal met Docker of Python), uw eigen server of
  PhishLens Cloud. De extensie stuurt niets ergens anders naartoe, behalve de meldingen die u zelf verstuurt (zie hieronder).
- De server controleert de e-mail en geeft een oordeel terug. Hij slaat
  geen e-mailinhoud, afzenders of onderwerpen op.
- Uw controlegeschiedenis blijft in uw browser. Ze wordt nooit geüpload.
- Er zijn geen accounts, geen analysetools, geen advertenties en geen
  verkoop van gegevens.
- U kunt een verkeerd oordeel melden of de statistieken van uw
  beoordelingen delen. Alleen wat u ziet en bevestigt wordt verstuurd:
  de tekst van de e-mail zonder namen, adressen, nummers en paden van
  links, of statistieken zonder enige e-mailinhoud.

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

## Meldingen die u zelf verstuurt

Onder elk oordeel toont PhishLens de herkende taal en een link
**Verkeerd oordeel? Meld het**; de weergave Statistieken heeft dezelfde
link voor controles die u als **Onjuist** hebt gemarkeerd, en een knop
**Mijn statistieken delen**. Er wordt niets verstuurd voordat u op
**Versturen** drukt nadat u hebt gelezen wat er wordt verstuurd.

| Melding | Wat wordt verstuurd | Wat nooit wordt verstuurd |
| --- | --- | --- |
| Verkeerd oordeel | Het onderwerp, de tekst en de domeinen van de links van die e-mail na anonimisering (namen na een aanhef of titel, uw eigen naam en adres zoals ze op de mailpagina staan, e-mailadressen, telefoonnummers, lange nummers zoals rekeningen, kaarten en codes, IBAN's, @namen en gebruikersnamen, het pad en de parameters van elke link), de tekst zoals u die hebt bewerkt, het oordeel, de scores, de beoordelingsroute, de herkende taal en uw antwoord, de versie van de extensie en de taal van de interface | Het adres van de afzender, de originele e-mail, de headers en de bijlagen |
| Statistieken | Voor elke controle in uw geschiedenis: de dag, waar gecontroleerd (Gmail, Outlook, venster van de extensie), het oordeel, de scores, of de afzender vertrouwd was, uw beoordeling Juist / Onjuist, de herkende taal en uw antwoord | Onderwerpen, afzenders, teksten, links |

Meldingen gaan naar PhishLens Cloud, welke server u ook voor de
controles gebruikt. De server anonimiseert de tekst een tweede keer met
dezelfde regels, bewaart de melding zonder uw IP-adres of andere
verzoekgegevens (het hieronder beschreven logboek van de webserver legt
het verzoek wel 30 dagen vast) en geeft een referentie terug. Meldingen
dienen alleen om PhishLens te meten en te verbeteren (bijvoorbeeld om
het tekstmodel te trainen op legitieme e-mails die het verkeerd
beoordeelde); ze worden nooit gepubliceerd of gedeeld. Ze worden
hooguit twee jaar bewaard. Om een melding te laten verwijderen, opent u
een issue op https://github.com/AnzouK/PhishLens/issues met de
referentie (de referentie alleen zegt niets over de melding).

Om melden vanuit de weergave Statistieken mogelijk te maken, blijft de
geanonimiseerde tekst van uw laatste Gmail- en Outlook-controles 7 dagen
in uw browser (hooguit 50 e-mails). Die verlaat de browser nooit, tenzij
u die controle meldt.

## Wat bewaard wordt, en hoe lang

| Gegevens | Waar | Hoe lang |
| --- | --- | --- |
| Controlegeschiedenis (onderwerp, afzender, oordeel, scores, belangrijkste woorden van de uitleg, herkende taal en uw antwoord) | Uw browser (`chrome.storage.local`) | Tot u ze wist (Statistieken, **Wissen**), hooguit de laatste 500 controles |
| Cache van uitleg | Uw browser | Tot de extensie wordt verwijderd |
| Geanonimiseerde tekst van recente Gmail- en Outlook-controles, voor meldingen | Uw browser | 7 dagen, hooguit 50 e-mails; gewist met de geschiedenis |
| Meldingen die u hebt verstuurd (geanonimiseerde tekst of statistieken, zie hierboven) | PhishLens Cloud | Hooguit twee jaar; op verzoek verwijderd met de referentie |
| Resultaten van de automatische controle (gespreks-ID, oordeel, score) | Uw browser | De laatste 500 e-mails |
| Instellingen | Uw browser | Tot ze gewijzigd worden |
| Linkoordelen (URL, oordeel, bron) | Servercache (SQLite) | 24 uur |
| Teruggestuurde resultaten (oordeel, scores, linkoordelen, woorden van de uitleg), gekoppeld aan een hash van de e-mail; niet de e-mail zelf | Geheugen van de server | 24 uur, of tot de server herstart |
| Tekst, headers en bijlagen van e-mails | Geheugen van de server, tijdens het verzoek | Niet opgeslagen |
| Metagegevens van verzoeken (tijd, pad, status, IP-adres, browser) | Applicatie- en webserverlogs van PhishLens Cloud | 30 dagen; de inhoud van verzoeken wordt nooit gelogd |

PhishLens Cloud telt ook oordelen per beoordelingsroute voor monitoring
(Prometheus-tellers). Dat zijn alleen getallen, zonder e-mailgegevens.

## Deze website

`phishlens.dev` plaatst geen cookies en gebruikt geen
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
| Toegang tot `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Controles naar de door u gekozen server sturen. |

## Uw keuzes

- Zet **Volledige headers lezen** of **Nieuwe e-mails automatisch
  controleren** op elk moment uit in de instellingen.
- Gebruik de lokale server, zodat e-mails uw computer nooit verlaten.
- Wis de geschiedenis in de weergave Statistieken, of verwijder de
  extensie om alles te wissen wat ze heeft opgeslagen.
- Als u nooit een melding verstuurt, verlaat niets uw browser behalve
  de controles zelf, naar de server die u hebt gekozen.

## Kinderen

PhishLens is niet gericht op kinderen en verzamelt niet bewust gegevens
over hen.

## Wijzigingen en contact

Wijzigingen in dit beleid staan in het [wijzigingslogboek](CHANGELOG.md)
van het project. Voor vragen opent u een issue op
https://github.com/AnzouK/PhishLens/issues, of meldt u een
beveiligingsprobleem vertrouwelijk zoals beschreven in
[SECURITY.md](SECURITY.md).
