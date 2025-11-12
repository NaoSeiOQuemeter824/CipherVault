# CipherVault – Rapport Prototype (v0)

Ce document résume ce qui a été implémenté pour le premier prototype.

## Objectif

- Lancer une application en ligne de commande simple
- Sélectionner un fichier (ex: .zip/.rar pour dossiers, images, ou tout fichier)
- Chiffrer/Déchiffrer pour soi-même (sans partage) via chiffrement hybride

## Architecture

- RSA-4096 (asymétrique) + AES-256-GCM (symétrique)
- Format de fichier unique: `.cvault`
- Stockage des clés: `~/.ciphervault/` (clé privée + clé publique)

### Flux de chiffrement (encrypt for self)

1. Génération clé AES aléatoire 256 bits + nonce GCM 96 bits
2. Chiffrement du contenu avec AES-256-GCM (confidentialité + intégrité via tag)
3. Chiffrement de la clé AES avec la clé publique RSA-4096 de l'utilisateur (OAEP/SHA-256)
4. Signature du hash SHA-256 du contenu original avec la clé privée (RSA-PSS)
5. Écriture du fichier `.cvault` contenant métadonnées + clé publique + clé AES chiffrée + signature + nonce + tag + ciphertext

### Flux de déchiffrement

1. Vérification du format `.cvault`
2. Vérification que la clé publique incluse correspond bien à l'utilisateur
3. Déchiffrement de la clé AES avec la clé privée
4. Déchiffrement AES-256-GCM (échec si tag invalide = contenu corrompu)
5. Vérification de la signature (RSA-PSS) sur le contenu déchiffré
6. Écriture du fichier d'origine

## Structure des fichiers

```
src/
  ciphervault/
    __init__.py
    crypto.py      # logique crypto: clés, encrypt/decrypt
    cli.py         # CLI minimale (interactive + commandes encrypt/decrypt)
  main.py          # point d'entrée `python src/main.py`

PROTOTYPE_RAPPORT.md   # ce document
README.md              # instructions d'exécution
requirements.txt       # dépendances
```

## Choix techniques

- RSA-4096 + OAEP(SHA-256) pour chiffrer la clé AES
- AES-256-GCM pour chiffrer les données et garantir l'intégrité (tag 16 bytes)
- Signature RSA-PSS (SHA-256) pour authentifier l'auteur et détecter toute altération
- Aucune compression automatique: si un dossier doit être chiffré, l'utilisateur crée d'abord un `.zip` (ou `.rar`)

## Limites actuelles (v0)

- Pas d'interface graphique: CLI seulement (simple et fiable)
- Pas d'options avancées: un flux basique encrypt/decrypt pour soi
- Les dossiers ne sont pas pris en charge directement (utiliser .zip/.rar)
- Pas encore de mode "pour un destinataire" ni de signature seule publique

## Étapes suivantes suggérées

- Ajouter un mode "pour un destinataire" (clé publique externe) et multi-destinataires
- Ajouter un mode "signature seule" pour partage public authentifié
- Option de sortie personnalisée et vérifications plus détaillées
- Détection automatique des types (images, archives) pour UX
- CLI packagée (entry point) et binaire exécutable
```