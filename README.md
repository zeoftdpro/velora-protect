# Velora Protect

Protège vos projets de code sur quatre fronts, depuis une seule commande ou un tableau de bord local :

| Volet | Ce que fait Velora |
|---|---|
| **Sécurité** | Détecte les secrets oubliés (clés AWS, GitHub, Stripe, OpenAI, Anthropic, clés privées, mots de passe…), les dépendances vulnérables (base publique **OSV.dev** : npm, PyPI, Go, Cargo, Composer, RubyGems) et les mauvaises configurations (TLS désactivé, debug, CORS `*`, Docker en root, `.env` commité…). Hook git qui **bloque les commits contenant des secrets**. |
| **Sites et applications** | Glissez un projet dans le tableau de bord, quelle que soit la techno (React, Vue, Next, PHP/WordPress/Laravel, Python, HTML/CSS, C/C++, Java, .NET, Go…) : XSS, injections SQL/commande, inclusion de fichiers, SSRF, redirections ouvertes, cookies, CSRF, jetons dans localStorage, absence de limitation des tentatives de connexion ou de hachage des mots de passe. **Mobile** : manifeste Android, Info.plist iOS, Flutter, React Native/Expo (app débogable, trafic en clair, certificats non vérifiés, jetons non chiffrés, R8 désactivé…). **Site en ligne** : HTTPS, certificat, TLS obsolète, en-têtes de sécurité, cookies, CORS, `.git`/`.env`/sauvegardes exposés, source maps et secrets dans les scripts publiés. Et la **configuration à copier** pour corriger (Nginx, Apache/.htaccess, Netlify, Vercel, Cloudflare, Next.js, Express, PHP, Django, Flask, IIS). |
| **Sauvegarde** | Archives ZIP versionnées et **vérifiées** vers disque externe, NAS, dossier OneDrive/Dropbox ou n'importe quel cloud via rclone. Inclut tout l'historique git et les bases de données. Rétention automatique (jour/semaine/mois), restauration, alertes webhook en cas d'échec ou de sauvegarde trop ancienne. |
| **Preuve d'antériorité** | Empreinte SHA-256 de chaque fichier, **horodatée par des autorités indépendantes** (RFC 3161 : FreeTSA, DigiCert) et **ancrée dans la blockchain Bitcoin** (OpenTimestamps). Vérifiable sans Velora, avec OpenSSL. Certificat lisible généré. |
| **Protection contre la copie** | Licence propriétaire (droit français) et en-têtes de copyright, **détection de copie** par empreintes de code (algorithme de MOSS, résiste au renommage de variables et au reformatage), audit de ce que votre build expose au client (source maps, secrets dans les bundles). |

Aucune dépendance : Python 3.10+ suffit. Rien n'est envoyé à l'extérieur, sauf : les noms/versions de dépendances à OSV.dev (scan), une **empreinte** (jamais le code) aux autorités d'horodatage, et vos alertes au webhook que vous configurez.

## Installation

```powershell
cd "C:\Users\liwey\Desktop\Projet Perso\Protect - Velora"
pip install -e .
```

La commande `velora` est alors disponible partout. (Sans installation : `python -m velora …` depuis ce dossier.)

## Démarrage rapide

```powershell
cd C:\chemin\vers\mon-projet
velora init --author "Votre Nom" --backup-dest "E:\Sauvegardes"
velora scan                       # analyse de sécurité
velora hook install               # bloque les commits contenant des secrets
velora backup run                 # première sauvegarde
velora proof create --archive     # preuve d'antériorité horodatée
velora protect fingerprint        # empreintes anti-copie
velora schedule --apply           # sauvegarde automatique chaque nuit à 2 h
velora ui                         # tableau de bord dans le navigateur
```

## Commandes

### Sécurité
```
velora scan [--offline] [--all] [--json] [--fail-on high] [--alert]
velora hook install | uninstall
```
- Code de sortie ≠ 0 si un problème atteint le seuil `--fail-on` : utilisable en CI (GitHub Actions, GitLab CI).
- Faux positif assumé : ajoutez `velora:ignore` en commentaire sur la ligne.
- Le `.gitignore` est respecté : un `.env` ignoré par git n'est pas signalé ; un `.env` non ignoré l'est.

### Sites et applications
```
velora scan                                # inclut désormais les règles web et mobile
velora web https://mon-site.fr [--json] [--fail-on high]
velora web http://localhost:3000 --allow-private    # site en développement
velora harden [--platform nginx|apache|netlify|vercel|cloudflare|nextjs|express|php|django|flask|iis]
```
- `velora web` ne fait que des lectures (une quarantaine de requêtes GET au plus, identifiées par l'User-Agent) : aucune attaque.
  Il refuse les adresses internes (localhost, 10.x, 192.168.x, 169.254.169.254…) sauf `--allow-private`, vérifie l'IP réellement
  contactée (pas de DNS rebinding) et revalide chaque redirection : il est conçu pour pouvoir tourner sur un serveur public.
- `velora harden` affiche les en-têtes de sécurité à ajouter pour votre hébergement, déduits du code si `--platform` est omis.
  La Content-Security-Policy proposée est stricte : testez-la d'abord en `Content-Security-Policy-Report-Only`.
- Analyse **statique** : le code n'est jamais exécuté. Les règles sont des heuristiques : un constat est à vérifier, et
  l'absence de constat ne garantit pas l'absence de faille (rien ne remplace un audit humain pour une application sensible).

### Sauvegarde
```
velora backup run [--force]          # ne refait rien si aucun fichier n'a changé
velora backup list
velora backup verify latest          # contrôle l'intégrité (SHA-256 de chaque fichier)
velora backup restore latest D:\Restauration
velora backup check                  # alerte si la dernière sauvegarde est trop ancienne
velora schedule [--every daily|hourly] [--time 02:00] [--with-scan] [--apply]
```
Destinations (`velora config add backup.destinations "<destination>"`) :
- un dossier : `E:\Sauvegardes`, `\\NAS\backup`, `C:\Users\moi\OneDrive\Sauvegardes` ;
- un remote [rclone](https://rclone.org) : `rclone:b2:mon-bucket/sauvegardes` (S3, Backblaze B2, SFTP, Google Drive…).

Mettez **au moins deux destinations**, dont une hors de votre ordinateur (règle 3-2-1).
Bases de données, dans `.velora/config.json` :
```json
"databases": [
  {"type": "sqlite", "name": "app", "path": "data/app.db"},
  {"type": "command", "name": "prod", "command": "pg_dump -Fc mabase", "extension": "dump"}
]
```
Contenu d'une archive : `files/` (le projet), `git/repo.bundle` (`git clone repo.bundle` restaure tout l'historique), `databases/`, `velora/` (config et preuves), `velora-manifest.json`.

> Les archives ne sont pas chiffrées : pour un cloud, utilisez un remote rclone `crypt`, ou un disque chiffré (BitLocker).

### Preuve d'antériorité
```
velora proof create [--note "v1.2 livrée au client"] [--archive] [--offline]
velora proof list
velora proof verify [<id>]
```
Chaque preuve est un dossier `.velora/proofs/<date>/` à **conserver précieusement** (il est inclus dans les sauvegardes) :
`manifest.json` (empreintes), `*.tsr` (jetons RFC 3161), `manifest.json.ots` (Bitcoin), `sources.zip` (copie exacte, avec `--archive`), `CERTIFICAT.txt`.

Vérification indépendante :
```
openssl ts -verify -data manifest.json -in manifest.freetsa.tsr -CAfile freetsa-cacert.pem
```
Pour OpenTimestamps, déposez `manifest.json` et `manifest.json.ots` sur https://opentimestamps.org quelques heures après (le temps qu'un bloc Bitcoin confirme).

**Valeur juridique.** Ces horodatages prouvent qu'un contenu précis existait au plus tard à une date donnée : c'est un élément de preuve solide et gratuit. Ils ne prouvent pas à eux seuls *qui* l'a écrit (gardez votre historique git) et ne sont pas des horodatages « qualifiés » eIDAS. Pour renforcer : enveloppe **e-Soleau** (INPI), dépôt à l'**APP** (Agence pour la Protection des Programmes), ou constat de commissaire de justice. En cas de litige, faites-vous conseiller par un avocat en propriété intellectuelle.

### Protection contre la copie
```
velora protect license [--type proprietary|mit] [--author "…"] [--contact "…"]
velora protect headers [--dry-run]
velora protect fingerprint                 # enregistre les empreintes du code actuel
velora protect compare <dossier|fichier>   # compare un code suspect au vôtre
velora protect audit                       # ce que votre build expose au client
```
`compare` indique la part du code suspect issue de votre projet, en mode **strict** (copie quasi littérale) et **flou** (variables renommées, code minifié), avec les fichiers d'origine.

**Soyons clairs** : rien de ce qui est envoyé à un navigateur ou à un téléphone n'est inviolable. L'obfuscation ralentit, elle n'empêche pas. La vraie protection, c'est de garder la logique sensible sur un serveur, puis d'affirmer vos droits (licence) et de pouvoir prouver une copie (preuves horodatées + empreintes). `velora protect audit` vous indique les outils adaptés à votre stack (javascript-obfuscator, PyArmor, R8…).

### Tableau de bord
```
velora ui [--port 8765]
```
Il écoute uniquement sur `127.0.0.1` et il est protégé par un jeton aléatoire (l'adresse s'affiche au lancement). Vous pouvez y gérer plusieurs projets.

**Analyse express** : glissez le dossier d'un site ou d'une application (ou un `.zip`) dans la zone en haut de page, et/ou saisissez
l'adresse du site en ligne. Les dépendances (`node_modules`, `vendor`…) ne sont pas envoyées ; le projet est extrait dans un dossier
temporaire (protégé contre les archives piégées : `../`, liens symboliques, bombes de décompression), analysé puis **effacé**.

### Configuration
```
velora config show
velora config set author "Votre Nom"
velora config set alerts.webhook_url "https://discord.com/api/webhooks/…"
velora config add backup.destinations "E:\Sauvegardes"
velora config set backup.retention.keep_daily 14
```
Alertes : Discord, Slack, Teams, Mattermost ou [ntfy.sh](https://ntfy.sh) (notification push sur téléphone, gratuit).

## Intégration continue (GitHub Actions)
```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install ./outils/velora && velora scan --fail-on high
```

## Tests
```
python -m unittest discover -s tests -t .
```
