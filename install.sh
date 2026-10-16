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

# 1. Ensure Node.js / npm is present
if ! command -v npm >/dev/null 2>&1; then
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew >/dev/null 2>&1; then
        echo -e "  ${ORANGE}›${NC} Node.js not found. Installing via Homebrew..."
        brew install node
    elif command -v apt-get >/dev/null 2>&1 && [ "$EUID" -eq 0 ]; then
        echo -e "  ${ORANGE}›${NC} Node.js not found. Installing via apt..."
        apt-get update -qq && apt-get install -y -qq nodejs npm python3 python3-venv python3-pip
    fi
fi

INSTALLED=0

# 2. Try global npm install
if command -v npm >/dev/null 2>&1; then
    echo -e "  ${ORANGE}›${NC} Installing TRACE CLI globally via npm (trace-sec)..."
    
    # Handle permissions: if not root and global dir is system-owned, configure user prefix
    NPM_PREFIX="$(npm prefix -g 2>/dev/null || echo '/usr/local')"
    if [ ! -w "$NPM_PREFIX" ] && [ "$EUID" -ne 0 ]; then
        mkdir -p "$HOME/.npm-global"
        npm config set prefix "$HOME/.npm-global"
        export PATH="$HOME/.npm-global/bin:$PATH"
        # Persist to shell profile
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            if [ -f "$rc" ] && ! grep -q '.npm-global/bin' "$rc"; then
                echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> "$rc"
            fi
        done
    fi

    if npm install -g trace-sec; then
        INSTALLED=1
        echo -e "  ${GREEN}✓${NC} Installed global 'trace' and 'trace-sec' CLI."
    fi
fi

# 3. Fallback to pip/pip3
if [ $INSTALLED -eq 0 ]; then
    PIP_CMD=""
    if command -v pip3 >/dev/null 2>&1; then
        PIP_CMD="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP_CMD="pip"
    fi

    if [ -n "$PIP_CMD" ]; then
        echo -e "  ${ORANGE}›${NC} Installing TRACE via $PIP_CMD..."
        $PIP_CMD install --upgrade trace-sec || $PIP_CMD install git+https://github.com/VK-Amogh/TRACE.git
        INSTALLED=1
    fi
fi

if [ $INSTALLED -eq 0 ]; then
    echo -e "  ${ORANGE}[!] Neither npm nor pip was found. Please install Node.js 18+ or Python 3.11+.${NC}"
    exit 1
fi

echo -e "\n${GREEN}✓ TRACE successfully installed!${NC}"
echo -e "Run ${CYAN}trace${NC} to start the interactive security audit wizard."
echo -e "Run ${CYAN}trace --help${NC} to view all commands.\n"
