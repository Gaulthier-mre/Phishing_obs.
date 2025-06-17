# PhishKiller - Détection de phishing pour Gmail

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

Un outil de détection de emails de phishing qui analyse le contenu et les expéditeurs pour identifier les menaces.

## Fonctionnalités

- Analyse des expéditeurs et détection de typosquatting
- Détection de mots-clés suspects
- Vérification des URLs intégrées
- Intégration avec l'API Gmail

## Configuration

1. Créez un projet dans Google Cloud Console
2. Activez l'API Gmail
3. Téléchargez le fichier `credentials.json` et placez-le dans le dossier du projet
4. Renommez `credentials.example.json` en `credentials.json` et ajoutez vos informations ainsi que token.pickle

## Utilisation

python phishkiller_pro.py
