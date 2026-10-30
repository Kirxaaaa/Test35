# Snake sur Netlify (comptes partagés)

Contenu : `index.html` (jeu + classement + console), `netlify/functions/api.mjs` (serveur),
`netlify.toml` et `package.json` (configuration). **Aucune variable d'environnement à ajouter.**

## Déploiement (GitHub, le plus simple)

1. Crée un dépôt GitHub (privé de préférence) et envoie-y le contenu de ce dossier.
2. Netlify > Add new project > Import from Git > choisis le dépôt > Deploy.
3. **Tout de suite après le déploiement** : ouvre le site, clique sur **Record** > « Créer un compte »
   et crée le compte nommé **Syndicate** avec le mot de passe de ton choix (ex. `Miami`).

> Le premier qui crée un compte « Syndicate » devient administrateur : fais-le avant de partager le lien.

## Jeux

La page principale a deux onglets : **Snake** et **Flappy** (adresse `#flappy`). Le record de Flappy est enregistré
dans le navigateur du joueur (il n'est pas dans le classement partagé, qui reste celui du Snake).

## Fonctionnement

- Un compte nommé **Syndicate** (majuscules/minuscules ignorées) a automatiquement tous les accès
  (Accueil, Louer, Acheter, Contrat, Locations, Comptes). Il n'existe plus de mot de passe dans Netlify.
- Les autres comptes n'ont que l'Accueil tant que Syndicate ne leur donne pas l'accès (onglet **Comptes**).
- La clé de signature des sessions est générée automatiquement et stockée dans Netlify Blobs.

## Sauvegarde des comptes

Onglet **Comptes** (connecté en Syndicate) :
- **Sauvegarde complète (JSON)** : télécharge tous les comptes (mots de passe chiffrés), les locations et le classement.
- **Restaurer une sauvegarde** : réimporte un fichier JSON (les comptes déjà présents ne sont pas écrasés).
  Utile pour reprendre les comptes d'un ancien site ou après une suppression.
- Les données sont aussi conservées par Netlify Blobs (Project > Blobs) et survivent aux redéploiements.

Garde le fichier de sauvegarde privé : il contient les empreintes des mots de passe.

## Mot de passe Syndicate oublié

Netlify > Blobs > store `accounts` : supprime l'entrée du compte Syndicate, puis recrée-le depuis le site.
