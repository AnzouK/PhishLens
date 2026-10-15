# Manufar sirri ta PhishLens

An sabunta ta ƙarshe: 15 ga Oktoba, 2026.

PhishLens ƙarin Chrome ne da ke duba ko imel phishing ne. Wannan shafin
yana bayyana bayanan da yake sarrafawa, inda suke zuwa da abin da ake
ajiyewa. Ya shafi ƙarin da kuma sabar da aka ɗauka, PhishLens Cloud, a
`anzouk.duckdns.org`.

## A taƙaice

- PhishLens yana karanta imel ne kawai idan ka nema (maɓallan
  **Duba**), ko ta atomatik idan ka kunna **Duba sababbin imel ta
  atomatik** a saituna (a kashe yake da farko).
- Ana aika imel ɗin zuwa sabar da ka zaɓa a saituna: kwamfutarka (Docker
  ko Python na gida), sabarka ta kanka, ko PhishLens Cloud. Ƙarin ba ya aika komai zuwa wani wuri daban, sai rahotannin da ka zaɓi aikawa (duba ƙasa).
- Sabar tana duba imel ɗin ta dawo da hukunci. Ba ta ajiye abin da ke
  cikin imel, masu aikawa ko jigogi.
- Tarihin bincikenka yana zama a burauzarka. Ba a taɓa aika shi ba.
- Babu asusu, babu bin diddigin masu ziyara, babu talla kuma babu
  sayar da bayanai.
- Za ka iya ba da rahoton hukunci da ba daidai ba, ko raba ƙididdigar
  ra'ayoyinka. Abin da ka gani kuma ka tabbatar kaɗai ake aikawa:
  rubutun imel ba tare da sunaye, adireshi, lambobi ko hanyoyin haɗi ba,
  ko ƙididdiga ba tare da wani abu na cikin imel ba.

## Abin da ƙarin yake karantawa

Lokacin da ake bincike, ƙarin yana karantawa daga shafin Gmail ko
Outlook da ke buɗe:

- rubutun saƙon, jigonsa da adireshin mai aikawa;
- inda hanyoyin haɗin cikin saƙon ke zuwa;
- alamun tabbatarwa da Gmail ke nunawa (wanda ya aika, wanda ya sa
  hannu);
- idan **Karanta cikakkun kanun saƙo** yana kunne (na asali), saƙon
  asali kamar yadda shafin "Nuna asali" na Gmail ke bayarwa: dukkan
  kanun saƙo da sassan rubutu, ba tare da fayilolin haɗe-haɗe ba;
- don binciken haɗe-haɗe, fayil ɗin da aka haɗa.

Tagar ƙarin kuma tana karanta fayilolin da ka jefa a cikinta da
rubutun da ka liƙa.

## Inda bayanai ke zuwa

Duk buƙatun bincike suna zuwa sabar guda ɗaya, wadda aka zaɓa a
saitunan ƙarin:

| Zaɓi | Inda imel ɗinka ke zuwa |
| --- | --- |
| Sabar ta gida | Kwamfutarka (`127.0.0.1:8000`). Babu abin da ke fita, sai binciken bayanan barazana da ke ƙasa. |
| URL na musamman | Sabar da ka shigar. Manufar mai ita ce ke aiki. |
| PhishLens Cloud | Sabar da marubucin PhishLens ke gudanarwa, a Oracle Cloud. Ba a ajiye komai (duba ƙasa). |

Sabar tana duba hanyoyin haɗin da aka samu a imel a sabis na bayanan
barazana. Don wannan, tana aika **adireshin hanyoyin haɗi kawai** (ba
rubutun imel, mai aikawa ko jigo ba):

- Google Safe Browsing (cikakkun URL, idan an saita maɓallin API);
- URLhaus na abuse.ch (cikakkun URL);
- Spamhaus DBL (sunayen yanki, ta DNS);
- PhishTank (ana kwatanta su da jerin da aka sauke a sabar; babu buƙata
  ga kowane imel).

## Rahotannin da ka zaɓi aikawa

A ƙarƙashin kowane hukunci, PhishLens yana nuna harshen da ya gano da
kuma hanyar haɗi **Hukunci ba daidai ba? Ka ba da rahoto**; shafin
Ƙididdiga yana da irin wannan hanyar haɗi don binciken da ka yi wa
alamar **Ba daidai ba**, da maɓallin **Raba ƙididdigata**. Babu abin da
ake aikawa har sai ka danna **Aika** bayan ka karanta abin da za a aika.

| Rahoto | Abin da ake aikawa | Abin da ba a taɓa aikawa |
| --- | --- | --- |
| Hukunci ba daidai ba | Jigo, rubutu da yankunan hanyoyin haɗin wannan imel bayan an cire bayanan sirri (sunaye bayan gaisuwa ko laƙabi, sunanka da adireshinka kamar yadda suke a shafin imel, adireshin imel, lambobin waya, dogayen lambobi kamar asusu, katin kuɗi da lambobin sirri, IBAN, @sunayen masu amfani, hanya da sigogin kowace hanyar haɗi), rubutun kamar yadda ka gyara shi, hukunci, maki, hanyar lissafi, harshen da aka gano da amsarka, sigar ƙarin da harshen manhajar | Adireshin mai aikawa, imel na asali, kanun saƙonsa da haɗe-haɗensa |
| Ƙididdiga | Ga kowane bincike a tarihinka: rana, inda aka yi shi (Gmail, Outlook, tagar ƙarin), hukunci, maki, ko mai aikawa amintacce ne, ra'ayinka Daidai / Ba daidai ba, harshen da aka gano da amsarka | Jigogi, masu aikawa, rubutu, hanyoyin haɗi |

Ana aika rahotanni zuwa PhishLens Cloud, ko wace sabar kake amfani da ita
don bincike. Sabar tana sake cire bayanan sirri daga rubutun da ƙa'idoji
iri ɗaya, tana ajiye rahoton ba tare da adireshin IP ɗinka ko wani bayanin
buƙata ba (bayanan ayyukan sabar yanar gizo da aka bayyana a ƙasa suna
ci gaba da rubuta buƙatar har kwana 30), sannan ta dawo da lambar shaida.
Ana amfani da rahotanni ne kawai don auna da inganta PhishLens (misali,
don horar da samfurin rubutu a kan imel na gaskiya da ya yi kuskure a
kansu); ba a taɓa wallafa su ko raba su. Ana ajiye su har shekara biyu
mafi yawa. Don a share rahoto, buɗe batu a
https://github.com/AnzouK/PhishLens/issues tare da lambar shaidarsa
(lambar shaidar kaɗai ba ta bayyana komai game da rahoton).

Don ba da damar ba da rahoto daga shafin Ƙididdiga, ana ajiye rubutun da
aka cire wa bayanan sirri na bincikenka na ƙarshe a Gmail da Outlook a
burauzarka har kwana 7 (imel 50 mafi yawa). Ba ya taɓa barin burauzar,
sai idan ka ba da rahoton wannan bincike.

## Abin da ake ajiyewa, da tsawon lokaci

| Bayani | Ina | Tsawon lokaci |
| --- | --- | --- |
| Tarihin bincike (jigo, mai aikawa, hukunci, maki, manyan kalmomin bayani, harshen da aka gano da amsarka) | Burauzarka (`chrome.storage.local`) | Har sai ka share shi (Ƙididdiga, **Share**), mafi yawa bincike 500 na ƙarshe |
| Ajiyar bayani | Burauzarka | Har sai an cire ƙarin |
| Rubutun da aka cire wa bayanan sirri na binciken Gmail da Outlook na baya-bayan nan, don rahotanni | Burauzarka | Kwana 7, imel 50 mafi yawa; ana share shi tare da tarihi |
| Rahotannin da ka aika (rubutu ba tare da bayanan sirri ba ko ƙididdiga, duba sama) | PhishLens Cloud | Shekara biyu mafi yawa; ana share su idan aka nema da lambar shaida |
| Sakamakon bincike ta atomatik (lambar tattaunawa, hukunci, maki) | Burauzarka | Imel 500 na ƙarshe |
| Saituna | Burauzarka | Har sai an canza su |
| Hukuncin hanyoyin haɗi (URL, hukunci, majiya) | Ajiyar sabar (SQLite) | Awa 24 |
| Sakamakon da aka dawo (hukunci, maki, hukuncin hanyoyin haɗi, kalmomin bayani), an haɗa su da lambar tantance imel; ba imel ɗin kansa ba | Ƙwaƙwalwar sabar | Awa 24, ko har sabar ta sake farawa |
| Rubutu, kanun saƙo da haɗe-haɗen imel | Ƙwaƙwalwar sabar, yayin buƙatar | Ba a ajiye su |
| Bayanan buƙatu (lokaci, hanya, matsayi, adireshin IP, burauza) | Bayanan ayyukan manhaja da sabar yanar gizo ta PhishLens Cloud | Kwana 30; ba a taɓa rubuta abin da ke cikin buƙatu |

PhishLens Cloud kuma yana ƙidaya hukunce-hukunce bisa hanyar lissafi,
don sa ido (ƙididdigar Prometheus). Lambobi ne kawai, babu bayanan imel.

## Wannan shafin yanar gizo

`anzouk.duckdns.org` ba ya saka kukis kuma ba ya amfani da rubutun bin
diddigi, don haka babu abin da za a amince da shi. Yawan ziyara yana
fitowa daga bayanan ayyukan sabar yanar gizo (shafi, lokaci, shafin da
aka fito, irin burauza, adireshin IP), ana karanta su da kayan aiki na
kai; ana ajiye su kwana 30 kuma ba a taɓa raba su. Shafin yana tambayar
API na jama'a na GitHub lambar sabuwar siga, wanda GitHub ke gani a
matsayin buƙata ta al'ada daga burauzarka.

## Izini

| Izini | Me yasa |
| --- | --- |
| `storage` | Ajiye saitunanka, tarihin bincike da ajiya a burauza. |
| `notifications` | Gargaɗe ka idan bincike ta atomatik ya sami imel na phishing. |
| `scripting` | Bayan sabuntawa, saka sabuwar sigar maɓallan bincike a shafukan Gmail da Outlook da ke buɗe, don kada ka sabunta su. |
| Samun dama ga `mail.google.com` | Ƙara maɓallan bincike da tutoci a Gmail da karanta imel ɗin da kake dubawa. |
| Samun dama ga Outlook a yanar gizo (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | Haka nan, a Outlook (bincike da hannu kawai). |
| Samun dama ga `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Aika bincike zuwa sabar da ka zaɓa. |

## Zaɓuɓɓukanka

- Kashe **Karanta cikakkun kanun saƙo** ko **Duba sababbin imel ta
  atomatik** a saituna a kowane lokaci.
- Yi amfani da sabar ta gida don kada imel su taɓa barin kwamfutarka.
- Share tarihi daga shafin Ƙididdiga, ko cire ƙarin don share duk abin
  da ya ajiye.
- Idan ba ka taɓa aika rahoto ba, babu abin da ke barin burauzarka sai
  binciken kansu, zuwa sabar da ka zaɓa.

## Yara

PhishLens ba don yara aka yi shi ba kuma ba ya tattara bayanai game da
su da gangan.

## Canje-canje da tuntuɓa

Ana jera canje-canjen wannan manufa a
[tarihin canje-canje](CHANGELOG.md) na aikin. Don tambayoyi, buɗe batu a
https://github.com/AnzouK/PhishLens/issues, ko ka ba da rahoton matsalar
tsaro a ɓoye kamar yadda aka bayyana a [SECURITY.md](SECURITY.md).
