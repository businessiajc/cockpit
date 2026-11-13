# Cockpit

Fenetre locale, en francais simple, pour suivre un agent Claude Code et explorer ses fichiers.
Lecture de fichiers uniquement : aucun jeton consomme, aucun appel reseau sortant, aucune dependance externe, aucun CDN.

## Utilisation

Version debutant : `Cockpit.exe` (un seul fichier, voir `release\LISEZ-MOI.txt`). Double-clic, la page s'ouvre.

Depuis les sources (Python via `uv`) :

```
uv run python -I server.py
```

Ouvre `http://127.0.0.1:8780/` (ports suivants si occupe). Arret : bouton « Quitter » dans la page, ou Ctrl+C / fermeture de la fenetre si lance depuis une console. L'exe (construit sans fenetre) s'arrete aussi seul 5 minutes apres la fermeture de la page.
Options : `--port`, `--sessions <dossier des JSONL>`, `--root <dossier suivi>`, `--config <config.json>`, `--profil <dossier>`, `--no-open`.
Tests : `uv run python -I test_cockpit.py`.

## Detection automatique

Aucun chemin n'est ecrit en dur. Priorite : option en ligne de commande > `config.json` (a cote du programme) > detection.

- Sessions : sous-dossier de `%USERPROFILE%\.claude\projects` dont le dernier fichier `.jsonl` est le plus recent.
- Dossier suivi (racine de la vue Cerveau) : champ `cwd` des premieres lignes de la session ; sinon decodage du nom du sous-dossier de session (les separateurs sont perdus a l'encodage : le programme cherche sur le disque le chemin qui redonne ce nom) ; sinon ecran d'accueil dans la page (champ dossier), memorise dans `config.json`.
- Seule ecriture du programme : `POST /api/setup` (en-tetes Host et Origin controles, JSON, dossier existant, pas un disque entier).
- `AGENTS.json` est cherche a la racine choisie ; s'il manque, la page explique comment le creer et comment nommer ses agents. Un modele est fourni : `AGENTS.exemple.json`.

## Les quatre onglets

- **Aujourd'hui** : etat (« travaille » si le fichier de session a bouge il y a moins de 3 min, sinon « En pause depuis X min »), 5 compteurs, bandeau orange en cas de probleme recent, plan du moment (derniere liste `update_plan`) et chronologie en phrases simples. Rafraichi toutes les 2 s, en pause si l'onglet est cache.
- **Mes agents** : une carte par agent (registre `AGENTS.json` + sous-agents detectes dans la session, sans doublon). Pastilles En cours / Termine / Planifie / Echec / En pause. Clic : fenetre « plan bleu ».
- **Missions a faire** : liste lue dans `MISSIONS.md` a la racine du dossier suivi (`## Titre` = groupe, `- [ ]` a faire, `- [x]` fait, lignes decalees = detail). Cockpit ne fait que la lire : c'est l'agent ou vous qui tenez le fichier.
- **Cerveau 3D** : carte mentale en canvas (projection en perspective ecrite a la main). Les menus sont deduits des dossiers de premier niveau du dossier suivi (8 plus gros + « Autres »), avec couleurs attribuees automatiquement, noms lisibles (underscores et tirets remplaces, majuscule), types par extension. Clic gauche maintenu : deplacer ; clic molette maintenu : tourner ; molette : zoom ; double-clic ou « Voir le schema » : fenetre plan bleu. Arborescence a gauche (recherche), details a droite, filtres, 300 noeuds visibles au plus.

Trois niveaux de description par fichier : resume (« Ce que ca fait »), « Comment ca marche » (fonctions et classes via `ast`, imports, titres Markdown), « Voir le code complet » (moins de 400 Ko, coloration simple, bouton Copier). Descriptions generiques pour les fichiers courants (README.md, LICENSE, requirements.txt, package.json, .gitignore, AGENTS.json, CLAUDE.md...) ; sinon docstring ou premiere ligne utile ; sinon « Pas encore de description ».

Ignores (sans tenir compte des majuscules) : `.git node_modules __pycache__ dist build venv .venv _secrets secrets .env logs tmp .cache .pytest_cache .idea .vscode` et caches de navigateur ; tout dossier contenant `Local State` ou `Preferences` (profil de navigateur) est aussi ignore.

## Profil local (facultatif)

Un dossier `profil_prive` a cote du programme (ou `--profil <dossier>`) est charge automatiquement : `profil.json` (menus, regroupements par nom de fichier ou de dossier, libelles, descriptions par nom, dossiers ignores en plus) et `descriptions.json` (descriptions par chemin relatif). Ce dossier est exclu du depot (`.gitignore`) et n'est pas embarque dans l'exe. Sans profil, tout est generique.

## Vie privee et securite

- 127.0.0.1 uniquement ; en-tete Host controle (403 sinon) ; `../`, chemins absolus et dossiers ignores refuses (404).
- Aucun envoi. Masquage des motifs `gho_`, `ghp_`, `github_pat_`, `sk-`, `AIza`, `AKIA`, `xox*-`, `Bearer`, JWT, cles privees, valeurs de `password=`, `token=`, `api_key=`, `secret=` dans les phrases, details, apercus et titres. `/api/code` et `/api/tech` refusent `.env*`, `.pem/.key/.pfx/.p12/.crt/.kdbx`. Le masquage repose sur des motifs : il ne garantit pas l'absence de tout secret de forme inconnue.

## Construction de l'exe

`uv run python -I make_icon.py cockpit.ico`, puis `uv run --with pyinstaller pyinstaller --onefile --noconsole --name Cockpit --icon <chemin absolu>\cockpit.ico --add-data <chemin absolu>\index.html;. server.py`. Version utilisee : PyInstaller 6.22.3. `profil_prive` n'est pas embarque. Voie normale de publication : `.github/workflows/build-exe.yml` (construction sur Windows propre a la publication d'une etiquette `v*`, avec SHA-256 joint).

## Verifie (2026-11-08)

- 45 tests OK (lecteur incremental, masquage, chemins, serveur, phrases, plan, agents, detection des sessions et du dossier, ecran d'accueil, classement generique, mecanisme de profil, description a trois niveaux, lecture du code, absence de ressource externe dans la page).
- `Cockpit.exe` (edition publique) lance depuis un dossier vide : `/`, `/api/tree`, `/api/live`, `/api/config` repondent 200, dossier et sessions detectes seuls, arret propre. SHA-256 dans `release\SHA256.txt`.
- Controle dans le navigateur integre (version precedente) : trois onglets sans erreur de console, pas de debordement horizontal, fenetre plan bleu lisible, aucune etiquette superposee dans le Cerveau.

## Non verifie / limites

- Teste seulement sous Windows 11, sur un seul poste ; pas sous Windows 10. SmartScreen et les antivirus ne sont pas testes : l'exe n'est pas signe, et un antivirus tiers a supprime des copies de l'exe sur le poste de test (cause non confirmee).
- Le classement generique, l'ecran d'accueil et les couleurs automatiques sont testes par des tests unitaires, pas dans un navigateur apres cette modification.
- Les formats JSONL de Claude Code ne sont pas documentes officiellement : le lecteur ignore ce qu'il ne reconnait pas. Seuls les 3 derniers Mo sont lus au premier chargement.
- Les sous-agents lances avant cette fenetre ne sont pas detectes ; les taches accomplies d'un agent planifie ne sont pas connues.
- Fichiers listes dans la carte : `.md .py .json .html .js .bat .sh .txt .toml .yml .yaml`, plus LICENSE et .gitignore. Pas de liens entre fichiers, hierarchie seulement.
- Commandes souris du Cerveau verifiees par evenements simules, pas avec une souris physique. Pas de mesure du CPU sur plusieurs heures.
- Console visible (pas d'icone dans la zone de notification).
