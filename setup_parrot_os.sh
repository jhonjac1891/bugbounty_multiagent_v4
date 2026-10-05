#!/usr/bin/env bash
# ============================================================
# Setup del entorno para el Bug Bounty Multi-Agent Framework
# Probado en Parrot OS / Kali Linux
# ============================================================
set -e

echo "[*] Actualizando repositorios..."
sudo apt update

echo "[*] Instalando dependencias base..."
sudo apt install -y golang-go python3-pip python3-venv nmap sqlmap git

echo "[*] Configurando GOPATH si no existe..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
grep -qxF 'export GOPATH="$HOME/go"' ~/.zshrc 2>/dev/null || echo 'export GOPATH="$HOME/go"' >> ~/.zshrc
grep -qxF 'export PATH="$PATH:$GOPATH/bin"' ~/.zshrc 2>/dev/null || echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.zshrc

echo "[*] Instalando ProjectDiscovery tools (subfinder, httpx, nuclei)..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[*] Actualizando plantillas de Nuclei..."
"$GOPATH/bin/nuclei" -update-templates

echo "[*] Creando entorno virtual de Python..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Instalando dependencias de Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "============================================================"
echo " Setup completo."
echo " Recuerda:"
echo "   1. Reinicia la terminal o ejecuta: source ~/.zshrc"
echo "   2. Activa el entorno virtual: source venv/bin/activate"
echo "   3. Edita config.yaml con el scope AUTORIZADO"
echo "   4. Ejecuta: python bugbounty_multiagent.py config.yaml <target>"
echo "============================================================"
