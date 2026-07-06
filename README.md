# Security Recon Tool

Un outil d'audit réseau professionnel écrit en Python, capable d'effectuer des scans SYN, de récupérer des bannières de service, et d'analyser des vulnérabilités (CVE) en temps réel.

## Fonctionnalités
- **Scan SYN rapide :** Utilisation de Scapy pour une découverte réseau furtive.
- **Enrichissement de données :** Fingerprinting OS et capture de bannières.
- **Reporting :** Export automatique des résultats en format CSV.
- **Interface GUI :** Interface intuitive avec barre de progression en temps réel.

## Utilisation
1. Installez les dépendances : `pip install -r requirements.txt`
2. Lancez avec les privilèges root : `sudo python3 scanner.py`

## Avertissement
Cet outil est destiné à un usage éducatif et dans un cadre d'audit autorisé uniquement. L'auteur décline toute responsabilité en cas d'utilisation malveillante.
