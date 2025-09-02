Déploiement sur EasyPanel (Docker / Docker Compose)

Pré-requis
- Un dépôt Git contenant ce projet.
- Un accès à EasyPanel (ou toute interface qui supporte Docker Compose).

Option A — Déploiement via Docker Compose (recommandé pour EasyPanel)
1. Poussez votre repo sur Git (GitHub/GitLab/Remote).
2. Dans EasyPanel, créez une nouvelle application Docker Compose et pointez vers le dépôt et la branche.
3. Indiquez le chemin du fichier `docker-compose.yml` (à la racine par défaut).
4. EasyPanel construira l'image puis démarrera le service exposé sur le port 80.

Avec reverse proxy nginx (TLS)
- Le dépôt contient une configuration `nginx/default.conf` qui reverse-proxy vers le service `web` sur le port 3000.
- EasyPanel peut monter vos certificats TLS dans `/etc/ssl/private/` à l'intérieur du conteneur nginx (fichiers `fullchain.pem` et `privkey.pem`). Assurez-vous de configurer les volumes ou la gestion TLS de la plateforme.

Exemple de mapping de volumes (EasyPanel UI):

 - Host path: /path/to/certs/fullchain.pem -> Container path: /etc/ssl/private/fullchain.pem
 - Host path: /path/to/certs/privkey.pem -> Container path: /etc/ssl/private/privkey.pem

Si vous préférez que EasyPanel gère TLS automatiquement (via sa fonctionnalité ACME), vous pouvez simplement exposer le port 80 et laisser la plateforme faire les redirections.

Option B — Construire et pousser l'image manuellement
1. Construire l'image localement :

```bash
docker build -t registry.example.com/mon-projet/passwordmanager:latest .
```

2. Pousser dans votre registre :

```bash
docker push registry.example.com/mon-projet/passwordmanager:latest
```

3. Dans EasyPanel, créez un service à partir de cette image et exposez le port 80.

Notes et recommandations
- Le `Dockerfile` fourni utilise un build multi-étape. Il exécute `npm run build` puis démarre le serveur Next en mode production (`npm start`).
- Le `docker-compose.yml` mappe le port 80 externe au port 3000 du conteneur (Next.js). Vous pouvez adapter le port externe selon vos besoins.
- Si vous utilisez des variables d'environnement sensibles, configurez-les via EasyPanel (ne les commitez pas dans le repo).

Dépannage rapide
- Si l'application ne démarre pas, vérifiez les logs du conteneur (`docker logs <container>` ou via l'UI EasyPanel).
- Assurez-vous que le script `start` dans `package.json` est bien `next start` (c'est le cas ici).

Si vous voulez, j'ajoute aussi un petit `healthcheck` Docker et un service `nginx` en front pour TLS/rewrites gérés par EasyPanel.
