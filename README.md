# CipherVault – Prototype (v1.0.1)

Minimal CLI app to encrypt/decrypt a single file for yourself using RSA-4096 + AES-256-GCM.

## Prérequis

- Python 3.10+
- Windows PowerShell (fourni) ou tout terminal

## Installation

1) Créer/activer un environnement virtuel (optionnel mais recommandé)

2) Installer les dépendances:

```
pip install -r requirements.txt
```

## Lancer le prototype

Afficher le menu interactif (encrypt/decrypt):

```
python src/main.py
```

Commandes directes:

```
# Chiffrer pour vous-même
python src/main.py encrypt <chemin_fichier>

# Déchiffrer un fichier .cvault
python src/main.py decrypt <chemin_fichier.cvault>

# Voir les clés et empreintes
python src/main.py --debug keys

# Afficher la version
python src/main.py --version
```

Notes:
- Pour chiffrer un dossier, compressez-le d'abord en .zip ou .rar, puis chiffrez l'archive.
- Les clés sont stockées sous: %USERPROFILE%\.ciphervault\ (clé privée et publique)
- Mode debug: ajoutez `--debug` avant la commande (ex: `python src/main.py --debug encrypt ...`) pour afficher des logs détaillés (génération/chargement des clés, étapes de chiffrement/déchiffrement).

## Versioning

- Format: MAJEUR.MINEUR.CORRECTIF (ex: 1.0.1)
- Règles:
	- Correctif (+0.0.1): petites améliorations, logs, corrections mineures
	- Mineur (+0.1.0): nouvelles fonctionnalités compatibles (ex: nouvelle commande)
	- Majeur (+1.0.0): changements importants/incompatibles
 
Version actuelle: 1.0.1 (ajout des logs `--debug` et de la commande `keys`).

## Sécurité (résumé)

- Données: AES-256-GCM (confidentialité + intégrité via tag)
- Clé: chiffrée avec RSA-4096 OAEP (SHA-256)
- Signature: RSA-PSS (SHA-256) sur le contenu original

Pour plus de théorie, voir `TEORIA_COMPLETA.md`.
