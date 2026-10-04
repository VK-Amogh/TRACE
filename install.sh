#!/usr/bin/env bash
# TRACE Universal One-Line Installer for macOS & Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/VK-Amogh/TRACE/main/install.sh | bash

set -e

GREEN='\033[0;32m'
ORANGE='\033[38;5;214m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}   ${CYAN}TRACE — Threat Reconnaissance & Attack-path Correlation Engine${NC}   ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}   ${ORANGE}Autonomous AI Security Verification for Coding Agents & CLI${NC}      ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}\n"

# Check for Node.js / npm
if command -v npm >/dev/null 2>&1; then
    echo -e "  ${ORANGE}›${NC} Installing TRACE CLI globally via npm..."
    npm install -g trace-sec
    echo -e "  ${GREEN}✓${NC} Installed global 'trace' and 'trace-sec' CLI."
elif command -v pip3 >/dev/null 2>&1; then
    echo -e "  ${ORANGE}›${NC} Installing TRACE via pip3 from GitHub..."
    pip3 install git+https://github.com/VK-Amogh/TRACE.git
    echo -e "  ${GREEN}✓${NC} Installed TRACE Python package."
elif command -v pip >/dev/null 2>&1; then
    echo -e "  ${ORANGE}›${NC} Installing TRACE via pip from GitHub..."
    pip install git+https://github.com/VK-Amogh/TRACE.git
    echo -e "  ${GREEN}✓${NC} Installed TRACE Python package."
else
    echo -e "  ${ORANGE}[!] Neither npm nor pip was found. Please install Python 3.10+ or Node.js.${NC}"
    exit 1
fi

echo -e "\n${GREEN}✓ TRACE successfully installed!${NC}"
echo -e "Run ${CYAN}trace${NC} to start the interactive security audit wizard."
echo -e "Run ${CYAN}trace --help${NC} to view all commands.\n"
