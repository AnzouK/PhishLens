# Politique de confidentialité de PhishLens

Dernière mise à jour : 2 octobre 2026.

PhishLens est une extension Chrome qui vérifie si des e-mails sont du
phishing. Cette page explique quelles données elle traite, où elles vont
et ce qui est conservé. Elle s'applique à l'extension et au serveur
hébergé, PhishLens Cloud, à l'adresse `anzouk.duckdns.org`.

## En bref

- PhishLens lit un e-mail seulement quand vous le demandez (les boutons
  **Analyser**), ou automatiquement si vous activez **Analyser
  automatiquement les nouveaux e-mails** dans les réglages (désactivé par
  défaut).
- L'e-mail est envoyé au serveur choisi dans les réglages : votre propre
  ordinateur (Docker ou Python en local), votre propre serveur, ou
  PhishLens Cloud. L'extension n'envoie rien ailleurs.
- Le serveur analyse l'e-mail et renvoie un verdict. Il ne stocke ni le
  contenu des e-mails, ni les expéditeurs, ni les objets.
- Votre historique d'analyses reste dans votre navigateur. Il n'est
  jamais envoyé.
- Pas de compte, pas de mesure d'audience, pas de publicité et aucune
  vente de données.

## Ce que l'extension lit

Lors d'une analyse, l'extension lit dans la page Gmail ou Outlook ouverte :

- le texte du message, son objet et l'adresse de l'expéditeur ;
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

## Ce qui est conservé, et combien de temps

| Donnée | Où | Durée |
| --- | --- | --- |
| Historique des analyses (objet, expéditeur, verdict, scores, principaux mots de l'explication) | Votre navigateur (`chrome.storage.local`) | Jusqu'à ce que vous l'effaciez (Statistiques, **Effacer**), au plus les 500 dernières analyses |
| Cache des explications | Votre navigateur | Jusqu'à la suppression de l'extension |
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

`anzouk.duckdns.org` ne dépose aucun cookie et n'utilise aucun script de
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
| Accès à `127.0.0.1:8000`, `localhost:8000`, `anzouk.duckdns.org` | Envoyer les analyses au serveur que vous avez choisi. |

## Vos choix

- Désactivez **Lire les en-têtes complets** ou **Analyser
  automatiquement les nouveaux e-mails** dans les réglages à tout moment.
- Utilisez le serveur local pour que les e-mails ne quittent jamais
  votre ordinateur.
- Effacez l'historique depuis la vue Statistiques, ou supprimez
  l'extension pour effacer tout ce qu'elle a enregistré.

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
