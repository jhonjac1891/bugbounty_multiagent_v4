# bugbounty_multiagent_v4
bugbounty _ multiagent _ v 4-2
# 🛡️ BugBounty MultiAgent v4.2

> Framework asíncrono multi-agente para pentesting automatizado, cobertura OWASP Top 10 + API Top 10, con GUI profesional estilo Qualys/Nessus.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Parrot%20OS-9400D3)

## 🎯 Características
- 21+ agentes especializados (OWASP Top 10 2021 + API Security Top 10)
- Reconocimiento previo: subdominios (subfinder), hosts vivos (httpx), puertos (nmap)
- GUI de escritorio con CustomTkinter
- Generación de reportes ejecutivos (estilo Qualys/Nessus)
- Validación de scope obligatoria (anti-uso fuera de autorización)

## 📸 Capturas
![GUI Preview](docs/screenshots/gui.png)  <img width="1420" height="816" alt="image (6)" src="https://github.com/user-attachments/assets/33421c6d-37cd-42a1-94e4-47f6ee5388d1" />


## ⚙️ Instalación
\`\`\`bash
git clone https://github.com/tuusuario/bugbounty_multiagent_v4-2.git
cd bugbounty_multiagent_v4-2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\`\`\`

## 🚀 Uso
\`\`\`bash
python src/bugbounty_multiagent_v4-2.py
\`\`\`

## ⚠️ Disclaimer legal
Este proyecto es exclusivamente para uso en programas autorizados de Bug Bounty, pentesting con contrato firmado, o laboratorios propios. El autor no se responsabiliza por uso indebido.

## 📄 Licencia
MIT

4. Comandos para subirlo desde Parrot OS 💻 / Kali Linux
bash
cd ~/Desktop/"Bug Bounty"/bugbounty_multiagent_v4-2
git init
git add .
git commit -m "Initial commit: BugBounty MultiAgent v4.2"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/bugbounty_multiagent_v4-2.git
git push -u origin main

---------------------------------------------------
English Version:
# 🛡️ BugBounty MultiAgent v4.2

> Asynchronous multi-agent framework for automated penetration testing, covering OWASP Top 10 + API Security Top 10, with a professional GUI inspired by Qualys/Nessus-style reporting.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Parrot%20OS%20%7C%20Kali%20Linux-9400D3)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 📋 Overview

BugBounty MultiAgent is an orchestrated security testing framework built around specialized autonomous agents, each one mapped to a specific OWASP vulnerability category. It automates reconnaissance, scanning, and executive-level reporting in a single pipeline — designed for authorized bug bounty programs, contracted penetration tests, and personal security labs.

## 🎯 Key Features

- **21+ specialized agents** covering OWASP Top 10 (2021) and OWASP API Security Top 10
- **Pre-engagement recon**: subdomain enumeration (`subfinder`), live host discovery (`httpx`), port scanning (`nmap`)
- **Desktop GUI** built with CustomTkinter for a modern, user-friendly experience
- **Executive-grade reporting**, styled after industry tools like Qualys and Nessus
- **Mandatory scope validation** — the framework refuses to run against targets outside the configured authorization scope

## 🏗️ Architecture
Recon Layer → Orchestrator → Specialized Agents (OWASP Top 10 / API Top 10) → Report Engine

text

## 📸 Screenshots

![GUI Preview](docs/screenshots/gui.png)

## ⚙️ Installation

```bash
git clone [https://github.com/yourusername/bugbounty_multiagent_v4-2.git](https://github.com/yourusername/bugbounty_multiagent_v4-2.git)
cd bugbounty_multiagent_v4-2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🚀 Usage

```bash
python src/bugbounty_multiagent_v4-2.py
```

## 📤 Publishing to GitHub (Parrot OS / Kali Linux)

```bash
cd ~/Desktop/"Bug Bounty"/bugbounty_multiagent_v4-2
git init
git add .
git commit -m "Initial commit: BugBounty MultiAgent v4.2"
git branch -M main
git remote add origin [https://github.com/yourusername/bugbounty_multiagent_v4-2.git](https://github.com/yourusername/bugbounty_multiagent_v4-2.git)
git push -u origin main
```

## 🤝 Contributing

Contributions, issue reports, and feature suggestions are welcome. Please open an issue before submitting a pull request to discuss proposed changes.

## ⚠️ Legal Disclaimer

This project is intended **exclusively** for use in authorized bug bounty programs, penetration testing engagements with a signed contract, or personal/isolated lab environments. The author assumes no responsibility for any misuse of this tool outside of properly authorized scopes.

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.



