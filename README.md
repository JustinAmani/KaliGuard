# 🛡️ KaliGuard AI

> Agent de cybersécurité défensif intelligent, propulsé par Claude AI, intégrant l'ensemble des outils Kali Linux.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=linux)
![Claude](https://img.shields.io/badge/AI-Claude%20Opus%204.6-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![Use](https://img.shields.io/badge/Use-Authorized%20Only-red)

---

## ⚠️ AVERTISSEMENT LÉGAL

**KaliGuard AI est conçu EXCLUSIVEMENT pour :**
- L'audit de vos propres systèmes et réseaux
- Les tests de pénétration avec autorisation écrite
- La formation et la recherche en cybersécurité
- La réponse aux incidents sur vos propres infrastructures

**L'utilisation contre des systèmes tiers sans autorisation est illégale.** Voir [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md).

---

## 🎯 Fonctionnalités

KaliGuard AI utilise Claude comme cerveau intelligent pour orchestrer **17 catégories d'outils Kali Linux** :

| Catégorie | Outils |
|-----------|--------|
| Reconnaissance & OSINT | nmap, masscan, theHarvester, whois, subfinder |
| Scan & Énumération | nikto, gobuster, enum4linux, wpscan |
| Analyse de vulnérabilités | OpenVAS, lynis, searchsploit |
| Forensics | Volatility 3, binwalk, YARA, chkrootkit |
| Réseau & Sniffing | tshark, tcpdump, Snort, Suricata |
| Cracking (récupération) | Hashcat, John, Hydra |
| WiFi (test propre réseau) | Aircrack-ng, Kismet, Wifite |
| Web Application | sqlmap, ffuf, ZAP, Burp Suite |
| Reverse Engineering | Ghidra, Radare2, YARA |
| Cryptographie | openssl, steghide, exiftool |
| Anonymat | Tor, macchanger, proxychains |

---

## 🏗️ Architecture

```
kaliguard/
├── main.py                  # CLI principal (Click + Rich)
├── agent.py                 # Cerveau Claude AI (tool_use)
├── tools/
│   ├── reconnaissance.py    # nmap, masscan, theHarvester...
│   ├── vulnerability.py     # OpenVAS, lynis, searchsploit...
│   ├── forensics.py         # Volatility, binwalk, YARA...
│   ├── network.py           # tshark, Snort, Suricata...
│   ├── cracking.py          # hashcat, john, hydra...
│   ├── wireless.py          # aircrack-ng, kismet...
│   ├── web.py               # sqlmap, ffuf, ZAP...
│   ├── reverse_eng.py       # ghidra, radare2...
│   ├── crypto.py            # openssl, steghide...
│   ├── anonymity.py         # tor, macchanger...
│   └── reporting.py         # PDF/HTML reports
├── database/
│   ├── devices.db           # Appareils découverts
│   ├── vulnerabilities.db   # Vulnérabilités trouvées
│   └── sessions.db          # Historique sessions
├── reports/                 # Rapports PDF auto-générés
├── logs/                    # Logs complets
├── install.sh               # Installation automatique
└── config.yaml              # Configuration
```

---

## 🚀 Installation (Kali Linux uniquement)

```bash
# 1. Cloner le repo
git clone https://github.com/JustinAmani/KaliGuard.git
cd KaliGuard

# 2. Lancer l'installation automatique
chmod +x install.sh
sudo ./install.sh

# 3. Configurer la clé API Claude
cp config.yaml.example config.yaml
nano config.yaml   # Ajouter votre ANTHROPIC_API_KEY

# OU via variable d'environnement
export ANTHROPIC_API_KEY='sk-ant-...'
```

---

## 💻 Utilisation

### Mode Chat Interactif (recommandé)
```bash
python main.py chat
```
L'IA comprend le français naturel :
```
Vous: Je pense être attaqué, analyse mon réseau 192.168.1.0/24
Vous: Fais un audit complet de 192.168.1.1
Vous: Analyse ce fichier suspect /tmp/malware.bin
Vous: Génère un rapport PDF de la session
```

### Commandes directes
```bash
# Scan réseau
python main.py scan 192.168.1.1

# Audit complet
python main.py audit 192.168.1.0/24

# Analyse forensique
python main.py forensics /path/to/suspicious/file

# Monitoring réseau
python main.py monitor eth0

# Générer rapport
python main.py report --session-id abc123

# Mode dry-run (simulation sans exécution)
python main.py --dry-run scan 192.168.1.1
```

---

## 🔄 Workflows Automatiques

### Workflow "Je suis attaqué"
```
nmap → tshark → Snort → analyse logs → rapport incident PDF
```

### Workflow "Audit complet réseau"
```
nmap → OpenVAS → nikto → enum4linux → rapport PDF
```

### Workflow "Analyse fichier suspect"
```
file → strings → binwalk → YARA → Volatility → rapport
```

### Workflow "Retrouve mon appareil volé"
```
arp-scan → nmap → netdiscover → SSH ping → alerte
```

---

## 🔒 Sécurité

- **Réseaux autorisés uniquement** : 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
- **Confirmation obligatoire** avant chaque action sensible
- **Mode `--dry-run`** pour simuler sans exécuter
- **Logs immuables** de toutes les actions
- **Validation IP** avant chaque commande

---

## 📋 Pré-requis

- Kali Linux (testé sur 2024.x)
- Python 3.10+
- Clé API Anthropic (Claude)
- Outils Kali installés (via `install.sh`)

---

## 📄 License

MIT License - Usage autorisé uniquement sur vos propres systèmes.

---

*Développé par [JustinAmani](https://github.com/JustinAmani) | Propulsé par [Claude AI](https://anthropic.com)*
