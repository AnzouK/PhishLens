# Politique de confidentialité de PhishLens

Dernière mise à jour : 16 octobre 2026.

PhishLens est une extension Chrome qui vérifie si des e-mails sont du
phishing. Cette page explique quelles données elle traite, où elles vont
et ce qui est conservé. Elle s'applique à l'extension et au serveur
hébergé, PhishLens Cloud, à l'adresse `phishlens.dev`.

## En bref

- PhishLens lit un e-mail seulement quand vous le demandez (les boutons
  **Analyser**), ou automatiquement si vous activez **Analyser
  automatiquement les nouveaux e-mails** dans les réglages (désactivé par
  défaut).
- L'e-mail est envoyé au serveur choisi dans les réglages : votre propre
  ordinateur (Docker ou Python en local), votre propre serveur, ou
  PhishLens Cloud. L'extension n'envoie rien ailleurs, hormis les signalements que vous choisissez d'envoyer (voir plus bas).
- Le serveur analyse l'e-mail et renvoie un verdict. Il ne stocke ni le
  contenu des e-mails, ni les expéditeurs, ni les objets.
- Votre historique d'analyses reste dans votre navigateur. Il n'est
  jamais envoyé.
- Pas de compte, pas de mesure d'audience, pas de publicité et aucune
  vente de données.
- Vous pouvez signaler un verdict faux, ou partager les statistiques de
  vos avis. Seul ce que vous voyez et confirmez est envoyé : le texte de
  l'e-mail sans noms, adresses, numéros ni chemins de liens, ou des
  statistiques sans aucun contenu d'e-mail.

## Ce que l'extension lit

Lors d'une analyse, l'extension lit dans la page Gmail ou Outlook ouverte :

- le texte du message, son objet, le nom et l'adresse de l'expéditeur ;
- les destinations des liens du message ;
- les indices d'authentification affichés par Gmail (envoyé par, signé
  par) ;
- avec **Lire les en-têtes complets** activé (par défaut), le message
  d'origine tel que le fournit la page « Afficher l'original » de Gmail :
  tous les en-têtes et les parties texte, sans les fichiers joints ;
- pour l'analyse d'une pièce jointe, le fichier joint.

La fenêtre de l'extension lit aussi les fichiers que vous y déposez et le
texte que vous y collez.

## Où vont les données

Toutes les demandes d'analyse vont à un seul serveur, choisi dans les
réglages de l'extension :

| Choix | Où va votre e-mail |
| --- | --- |
| Serveur local | Votre propre ordinateur (`127.0.0.1:8000`). Rien n'en sort, sauf les vérifications de renseignement sur les menaces ci-dessous. |
| URL personnalisée | Le serveur que vous avez saisi. La politique de son propriétaire s'applique. |
| PhishLens Cloud | Le serveur hébergé géré par l'auteur de PhishLens, sur Oracle Cloud. Rien n'est stocké (voir ci-dessous). |

Le serveur vérifie les liens trouvés dans un e-mail auprès de services de
renseignement sur les menaces. Pour cela, il envoie **uniquement les
adresses des liens** (jamais le texte de l'e-mail, l'expéditeur ou
l'objet) :

- Google Safe Browsing (URL complètes, quand une clé d'API est
  configurée) ;
- URLhaus d'abuse.ch (URL complètes) ;
- Spamhaus DBL (noms de domaine, via le DNS) ;
- PhishTank (comparaison avec une liste téléchargée sur le serveur ;
  aucune requête par e-mail).

## Les signalements que vous choisissez d'envoyer

Sous chaque verdict, PhishLens indique la langue détectée et propose un
lien **Verdict faux ? Le signaler** ; la vue Statistiques propose le même
lien pour les analyses marquées **Faux**, et un bouton **Partager mes
statistiques**. Rien n'est envoyé avant que vous appuyiez sur
**Envoyer** après avoir relu ce qui sera envoyé.

| Signalement | Ce qui est envoyé | Ce qui n'est jamais envoyé |
| --- | --- | --- |
| Verdict faux | L'objet, le texte et les domaines des liens de cet e-mail après anonymisation (noms après une salutation ou un titre, votre propre nom et adresse tels qu'ils apparaissent sur la page de la messagerie, adresses e-mail, numéros de téléphone, longs nombres comme les comptes, cartes et codes, IBAN, @pseudos et noms d'utilisateur, chemin et paramètres de chaque lien), le texte tel que vous l'avez modifié, le verdict, les scores, le mode de calcul, la langue détectée et votre réponse, la version de l'extension et la langue de l'interface | L'adresse de l'expéditeur, l'e-mail d'origine, ses en-têtes et ses pièces jointes |
| Statistiques | Pour chaque analyse de votre historique : le jour, où elle a été faite (Gmail, Outlook, fenêtre de l'extension), le verdict, les scores, si l'expéditeur était de confiance, votre avis Juste / Faux, la langue détectée et votre réponse | Objets, expéditeurs, textes, liens |

Les signalements vont à PhishLens Cloud, quel que soit le serveur que
vous utilisez pour les analyses. Le serveur anonymise le texte une
seconde fois avec les mêmes règles, enregistre le signalement sans votre
adresse IP ni aucune autre donnée de la requête (le journal du serveur
web décrit plus bas enregistre toutefois la requête pendant 30 jours),
et renvoie une référence. Les signalements servent uniquement à mesurer
et à améliorer PhishLens (par exemple à entraîner le modèle de texte sur
des e-mails légitimes qu'il a mal jugés) ; ils ne sont jamais publiés ni
partagés. Ils sont conservés au plus deux ans. Pour faire supprimer un
signalement, ouvrez un ticket sur
https://github.com/AnzouK/PhishLens/issues en indiquant sa référence (la
référence seule ne révèle rien du signalement).

Pour permettre un signalement depuis la vue Statistiques, le texte
anonymisé de vos dernières analyses Gmail et Outlook est conservé dans
votre navigateur pendant 7 jours (50 e-mails au plus). Il ne quitte
jamais le navigateur, sauf si vous signalez cette analyse.

## Ce qui est conservé, et combien de temps

| Donnée | Où | Durée |
| --- | --- | --- |
| Historique des analyses (objet, expéditeur, verdict, scores, principaux mots de l'explication, langue détectée et votre réponse) | Votre navigateur (`chrome.storage.local`) | Jusqu'à ce que vous l'effaciez (Statistiques, **Effacer**), au plus les 500 dernières analyses |
| Cache des explications | Votre navigateur | Jusqu'à la suppression de l'extension |
| Texte anonymisé des analyses Gmail et Outlook récentes, pour les signalements | Votre navigateur | 7 jours, 50 e-mails au plus ; effacé avec l'historique |
| Signalements que vous avez envoyés (texte anonymisé ou statistiques, voir plus haut) | PhishLens Cloud | Au plus deux ans ; supprimés sur demande avec la référence |
| Résultats de l'analyse automatique (identifiant de conversation, verdict, score) | Votre navigateur | Les 500 derniers e-mails |
| Réglages | Votre navigateur | Jusqu'à leur modification |
| Verdicts des liens (URL, verdict, source) | Cache du serveur (SQLite) | 24 heures |
| Résultats renvoyés (verdict, scores, verdicts des liens, mots de l'explication), indexés par une empreinte de l'e-mail ; pas l'e-mail lui-même | Mémoire du serveur | 24 heures, ou jusqu'au redémarrage du serveur |
| Texte, en-têtes et pièces jointes des e-mails | Mémoire du serveur, pendant la requête | Non stockés |
| Métadonnées des requêtes (heure, chemin, statut, adresse IP, navigateur) | Journaux de l'application et du serveur web de PhishLens Cloud | 30 jours ; le contenu des requêtes n'est jamais journalisé |

PhishLens Cloud compte aussi les verdicts par mode de calcul, pour la
supervision (compteurs Prometheus). Ce sont uniquement des nombres, sans
aucune donnée d'e-mail.

## Ce site

`phishlens.dev` ne dépose aucun cookie et n'utilise aucun script de
suivi : il n'y a donc rien à accepter. Le nombre de visites provient des
journaux du serveur web (page, heure, page d'origine, type de navigateur,
adresse IP), lus avec un outil auto-hébergé ; ils sont conservés 30
jours et jamais partagés. La page demande à l'API publique de GitHub le
numéro de la dernière version, ce que GitHub voit comme une requête
ordinaire de votre navigateur.

## Autorisations

| Autorisation | Pourquoi |
| --- | --- |
| `storage` | Conserver vos réglages, votre historique et les caches dans le navigateur. |
| `notifications` | Vous avertir quand l'analyse automatique trouve un e-mail de phishing. |
| `scripting` | Après une mise à jour, installer la nouvelle version des boutons d'analyse dans les onglets Gmail et Outlook déjà ouverts, pour que vous n'ayez pas à les actualiser. |
| Accès à `mail.google.com` | Ajouter les boutons d'analyse et les bannières à Gmail et lire l'e-mail que vous analysez. |
| Accès à Outlook sur le web (`outlook.office.com`, `outlook.office365.com`, `outlook.live.com`) | La même chose, dans Outlook (analyses manuelles seulement). |
| Accès à `127.0.0.1:8000`, `localhost:8000`, `phishlens.dev` | Envoyer les analyses au serveur que vous avez choisi. |

## Vos choix

- Désactivez **Lire les en-têtes complets** ou **Analyser
  automatiquement les nouveaux e-mails** dans les réglages à tout moment.
- Utilisez le serveur local pour que les e-mails ne quittent jamais
  votre ordinateur.
- Effacez l'historique depuis la vue Statistiques, ou supprimez
  l'extension pour effacer tout ce qu'elle a enregistré.
- Si vous n'envoyez jamais de signalement, rien ne quitte votre
  navigateur hormis les analyses elles-mêmes, vers le serveur choisi.

## Enfants

PhishLens ne s'adresse pas aux enfants et ne collecte pas sciemment de
données les concernant.

## Modifications et contact

Les modifications de cette politique sont listées dans le
[journal des modifications](CHANGELOG.md) du projet. Pour toute
question, ouvrez un ticket sur
https://github.com/AnzouK/PhishLens/issues, ou signalez un problème de
sécurité de façon confidentielle comme décrit dans
[SECURITY.md](SECURITY.md).
