#!/bin/bash
# =============================================================================
# KaliGuard AI - Installation Script
# =============================================================================
# LEGAL: This tool is for authorized use only on networks/systems you own
# or have explicit written permission to test.
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}${BOLD}"
echo " ██╗  ██╗ █████╗ ██╗      ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗"
echo " ██║ ██╔╝██╔══██╗██║      ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
echo " █████╔╝ ███████║██║      ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
echo " ██╔═██╗ ██╔══██║██║      ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
echo " ██║  ██╗██║  ██║███████╗ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
echo " ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"
echo ""
echo "           AI-Powered Defensive Security Agent - Installer"
echo -e "${NC}"

# =============================================================================
# STEP 1: Check OS
# =============================================================================
echo -e "${BOLD}[STEP 1/9] Checking operating system...${NC}"

if [ ! -f /etc/os-release ]; then
    echo -e "${RED}[ERROR] /etc/os-release not found. Cannot determine OS.${NC}"
    exit 1
fi

source /etc/os-release

if echo "$ID $ID_LIKE $PRETTY_NAME" | grep -qi "kali"; then
    echo -e "${GREEN}[OK] Kali Linux detected: $PRETTY_NAME${NC}"
elif echo "$ID $ID_LIKE $PRETTY_NAME" | grep -qi "debian\|ubuntu\|parrot"; then
    echo -e "${YELLOW}[WARN] Detected Debian/Ubuntu-based OS: $PRETTY_NAME${NC}"
    echo -e "${YELLOW}       KaliGuard AI is optimized for Kali Linux but may work on this OS.${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation aborted.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[ERROR] KaliGuard AI requires Kali Linux (or Debian/Ubuntu-based OS).${NC}"
    echo -e "${RED}       Detected: $PRETTY_NAME${NC}"
    exit 1
fi

# Check root or sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[WARN] Not running as root. Some packages may fail to install.${NC}"
    SUDO="sudo"
else
    SUDO=""
    echo -e "${GREEN}[OK] Running as root.${NC}"
fi

# =============================================================================
# STEP 2: Update apt
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 2/9] Updating package lists...${NC}"

$SUDO apt-get update -qq 2>&1 | tail -5
echo -e "${GREEN}[OK] Package lists updated.${NC}"

# =============================================================================
# STEP 3: Install system packages
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 3/9] Installing Kali Linux security tools...${NC}"
echo -e "${YELLOW}This may take a while depending on your internet connection.${NC}"

PACKAGES=(
    # Reconnaissance
    nmap
    masscan
    nikto
    gobuster
    dirb
    enum4linux
    wpscan
    dnsenum
    whois
    dnsutils
    theharvester
    recon-ng
    amass
    # Vulnerability Scanning
    openvas
    lynis
    exploitdb
    # Exploitation
    metasploit-framework
    # Network Tools
    wireshark
    tshark
    tcpdump
    snort
    suricata
    netdiscover
    arp-scan
    bettercap
    p0f
    # Wireless
    aircrack-ng
    kismet
    wifite
    reaver
    # Password Cracking
    hashcat
    john
    hydra
    medusa
    crunch
    cewl
    hash-identifier
    # Web Testing
    sqlmap
    # Forensics
    volatility3
    binwalk
    foremost
    chkrootkit
    rkhunter
    yara
    # Reverse Engineering
    ghidra
    radare2
    gdb
    ltrace
    strace
    binutils
    # Crypto/Steg
    steghide
    stegseek
    exiftool
    zsteg
    # Anonymity
    tor
    macchanger
    proxychains4
    # Utilities
    curl
    wget
    git
    python3
    python3-pip
    python3-venv
    sqlite3
    jq
    net-tools
    ncat
    socat
)

FAILED_PACKAGES=()

for pkg in "${PACKAGES[@]}"; do
    echo -n "  Installing $pkg... "
    if $SUDO apt-get install -y -qq "$pkg" > /tmp/apt_install_${pkg}.log 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        # Try alternative package names
        ALTERNATE=""
        case "$pkg" in
            exploitdb) ALTERNATE="exploitdb-legacy" ;;
            volatility3) ALTERNATE="python3-volatility3" ;;
            ghidra) ALTERNATE="" ;;  # Requires manual install
        esac
        if [ -n "$ALTERNATE" ] && $SUDO apt-get install -y -qq "$ALTERNATE" > /dev/null 2>&1; then
            echo -e "${YELLOW}OK (via $ALTERNATE)${NC}"
        else
            echo -e "${YELLOW}SKIP (not available in repos)${NC}"
            FAILED_PACKAGES+=("$pkg")
        fi
    fi
done

if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
    echo -e "${YELLOW}[WARN] The following packages were not installed (may require manual install):${NC}"
    for pkg in "${FAILED_PACKAGES[@]}"; do
        echo -e "  ${YELLOW}- $pkg${NC}"
    done
fi

# Install Subfinder (Go-based, not in apt)
echo -n "  Installing subfinder (Go binary)... "
if command -v subfinder &> /dev/null; then
    echo -e "${GREEN}Already installed${NC}"
elif command -v go &> /dev/null; then
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1 && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}SKIP${NC}"
else
    echo -e "${YELLOW}SKIP (Go not installed)${NC}"
fi

echo -e "${GREEN}[OK] Security tools installation complete.${NC}"

# =============================================================================
# STEP 4: Python dependencies
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 4/9] Installing Python dependencies...${NC}"

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$INSTALL_DIR"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
echo -e "  Python version: ${GREEN}$PYTHON_VERSION${NC}"

# Create virtual environment (optional but recommended)
if [ ! -d "venv" ]; then
    echo -n "  Creating Python virtual environment... "
    python3 -m venv venv && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}SKIP (using system Python)${NC}"
fi

# Activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo -e "  ${GREEN}Virtual environment activated.${NC}"
fi

# Install Python packages
echo -n "  Installing pip packages from requirements.txt... "
if pip install -r requirements.txt -q 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}Some packages failed. Trying with --break-system-packages...${NC}"
    pip install -r requirements.txt -q --break-system-packages 2>&1 || echo -e "${YELLOW}Some packages may not have installed correctly.${NC}"
fi

echo -e "${GREEN}[OK] Python dependencies installed.${NC}"

# =============================================================================
# STEP 5: Create directory structure
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 5/9] Creating directory structure...${NC}"

DIRS=(
    "database"
    "reports"
    "logs"
    "wordlists"
    "captures"
    "evidence"
    "tmp"
)

for dir in "${DIRS[@]}"; do
    mkdir -p "$dir"
    echo -e "  ${GREEN}Created: $dir/${NC}"
done

# =============================================================================
# STEP 6: Initialize databases
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 6/9] Initializing databases...${NC}"

if python3 database/__init__.py; then
    echo -e "${GREEN}[OK] Databases initialized successfully.${NC}"
else
    echo -e "${YELLOW}[WARN] Database initialization encountered issues.${NC}"
fi

# =============================================================================
# STEP 7: Symlink wordlists
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 7/9] Setting up wordlists...${NC}"

if [ -d /usr/share/wordlists ]; then
    if [ ! -L wordlists/system ]; then
        ln -sf /usr/share/wordlists wordlists/system
        echo -e "  ${GREEN}Linked /usr/share/wordlists -> wordlists/system${NC}"
    else
        echo -e "  ${GREEN}Wordlists symlink already exists.${NC}"
    fi

    # Decompress rockyou if needed
    if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        echo -n "  Decompressing rockyou.txt.gz... "
        $SUDO gunzip /usr/share/wordlists/rockyou.txt.gz && echo -e "${GREEN}OK${NC}" || echo -e "${YELLOW}SKIP${NC}"
    fi

    if [ -f /usr/share/wordlists/rockyou.txt ]; then
        echo -e "  ${GREEN}rockyou.txt available.${NC}"
    fi
else
    echo -e "  ${YELLOW}/usr/share/wordlists not found. Install wordlists with: sudo apt install wordlists${NC}"
fi

# =============================================================================
# STEP 8: Setup configuration
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 8/9] Setting up configuration...${NC}"

if [ ! -f config.yaml ]; then
    if [ -f config.yaml.example ]; then
        cp config.yaml.example config.yaml
        echo -e "  ${GREEN}Copied config.yaml.example -> config.yaml${NC}"
    else
        echo -e "  ${YELLOW}config.yaml not found. Please create it manually from config.yaml.example${NC}"
    fi
else
    echo -e "  ${GREEN}config.yaml already exists.${NC}"
fi

# Make main.py executable
chmod +x main.py 2>/dev/null || true
echo -e "  ${GREEN}Made main.py executable.${NC}"

# Create a wrapper script for easy invocation
cat > kaliguard << 'WRAPPER'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi
python3 "$SCRIPT_DIR/main.py" "$@"
WRAPPER

chmod +x kaliguard
echo -e "  ${GREEN}Created kaliguard wrapper script.${NC}"

# Create logs directory and initial log file
touch logs/kaliguard.log
echo -e "  ${GREEN}Created logs/kaliguard.log${NC}"

# =============================================================================
# STEP 9: Health check
# =============================================================================
echo ""
echo -e "${BOLD}[STEP 9/9] Running health check...${NC}"

HEALTH_OK=true

# Check critical tools
CRITICAL_TOOLS=(nmap nikto sqlmap hashcat john hydra tcpdump)
OPTIONAL_TOOLS=(gobuster masscan metasploit openvas volatility3 ghidra radare2 aircrack-ng)

echo ""
echo -e "  ${BOLD}Critical Tools:${NC}"
for tool in "${CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        VERSION=$("$tool" --version 2>&1 | head -1 | grep -oP 'v?[\d.]+' | head -1 || echo "installed")
        echo -e "    ${GREEN}[✓] $tool $VERSION${NC}"
    else
        echo -e "    ${RED}[✗] $tool NOT FOUND${NC}"
        HEALTH_OK=false
    fi
done

echo ""
echo -e "  ${BOLD}Optional Tools:${NC}"
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "    ${GREEN}[✓] $tool${NC}"
    else
        echo -e "    ${YELLOW}[~] $tool not installed (optional)${NC}"
    fi
done

# Check Python import
echo ""
echo -n "  Checking Python anthropic library... "
if python3 -c "import anthropic; print('OK')" 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED - Run: pip install anthropic${NC}"
    HEALTH_OK=false
fi

echo -n "  Checking Python rich library... "
if python3 -c "import rich; print('OK')" 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED - Run: pip install rich${NC}"
    HEALTH_OK=false
fi

echo -n "  Checking Python click library... "
if python3 -c "import click; print('OK')" 2>/dev/null | grep -q "OK"; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED - Run: pip install click${NC}"
    HEALTH_OK=false
fi

# Check ANTHROPIC_API_KEY
echo ""
echo -n "  Checking ANTHROPIC_API_KEY... "
if [ -n "$ANTHROPIC_API_KEY" ]; then
    KEY_PREVIEW="${ANTHROPIC_API_KEY:0:8}...${ANTHROPIC_API_KEY: -4}"
    echo -e "${GREEN}Set ($KEY_PREVIEW)${NC}"
else
    echo -e "${YELLOW}NOT SET${NC}"
    echo -e "  ${YELLOW}  -> Export it with: export ANTHROPIC_API_KEY='your-key-here'${NC}"
    echo -e "  ${YELLOW}  -> Add to ~/.bashrc or ~/.zshrc for persistence${NC}"
fi

# Check databases
echo ""
echo -n "  Checking databases... "
if [ -f database/sessions.db ] && [ -f database/devices.db ] && [ -f database/vulnerabilities.db ]; then
    echo -e "${GREEN}All 3 databases present${NC}"
else
    echo -e "${YELLOW}Some databases missing (run: python3 database/__init__.py)${NC}"
fi

# =============================================================================
# FINAL SUMMARY
# =============================================================================
echo ""
echo "=============================================================================="

if $HEALTH_OK; then
    echo -e "${GREEN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║              INSTALLATION SUCCESSFUL!                     ║"
    echo "  ║                                                           ║"
    echo "  ║  KaliGuard AI is ready to use.                           ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
else
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║         INSTALLATION COMPLETE (WITH WARNINGS)            ║"
    echo "  ║                                                           ║"
    echo "  ║  Some components may need manual installation.           ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi

echo ""
echo -e "${BOLD}NEXT STEPS:${NC}"
echo ""
echo -e "  1. Set your Anthropic API key:"
echo -e "     ${CYAN}export ANTHROPIC_API_KEY='sk-ant-your-key-here'${NC}"
echo ""
echo -e "  2. Start interactive AI chat mode:"
echo -e "     ${CYAN}./kaliguard chat${NC}"
echo ""
echo -e "  3. Run a quick scan (dry-run first):"
echo -e "     ${CYAN}./kaliguard --dry-run scan 192.168.1.1${NC}"
echo ""
echo -e "  4. Full audit of your network:"
echo -e "     ${CYAN}./kaliguard audit 192.168.1.0/24 --depth standard${NC}"
echo ""
echo -e "  5. Check system status:"
echo -e "     ${CYAN}./kaliguard status${NC}"
echo ""
echo -e "${RED}${BOLD}LEGAL REMINDER:${NC}${RED} Only use KaliGuard AI on networks/systems you own"
echo -e "or have explicit written permission to test. See LEGAL_DISCLAIMER.md${NC}"
echo ""
echo "=============================================================================="
