#!/usr/bin/env bash
# ==============================================================================
# SecureVault: Automated Linux Setup & Docker Deployment Script
# Installs Docker & Docker Compose (if missing) and starts the service.
# ==============================================================================

set -e

GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  SecureVault: Automated Docker Setup & Launcher            ${NC}"
echo -e "${BLUE}============================================================${NC}"

# 1. Check for root / sudo privileges
SUDO=""
if [ "$EUID" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo -e "${RED}Error: This script requires root or sudo privileges to install Docker.${NC}"
    exit 1
  fi
fi

# 2. Check if Docker is installed
if ! command -v docker >/dev/null 2>&1; then
  echo -e "${YELLOW}[!] Docker not found. Installing Docker Engine automatically...${NC}"
  
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  elif command -v wget >/dev/null 2>&1; then
    wget -qO /tmp/get-docker.sh https://get.docker.com
  else
    echo -e "${YELLOW}[*] Installing curl...${NC}"
    $SUDO apt-get update && $SUDO apt-get install -y curl || $SUDO yum install -y curl
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  fi

  $SUDO sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  
  # Start and enable Docker service
  $SUDO systemctl enable --now docker || true
  
  # Add current user to docker group if non-root
  if [ "$USER" != "root" ] && [ -n "$USER" ]; then
    $SUDO usermod -aG docker "$USER" || true
  fi
  
  echo -e "${GREEN}[✓] Docker installed successfully!${NC}"
else
  echo -e "${GREEN}[✓] Docker is already installed.${NC}"
fi

# 3. Check for Docker Compose plugin or binary
COMPOSE_CMD=""
if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
else
  echo -e "${YELLOW}[!] Docker Compose plugin not found. Installing compose plugin...${NC}"
  $SUDO apt-get update && $SUDO apt-get install -y docker-compose-plugin || true
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  else
    COMPOSE_CMD="$SUDO docker compose"
  fi
fi

# 4. Setup environment file (.env) if missing
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    echo -e "${BLUE}[*] Creating .env configuration from .env.example...${NC}"
    cp .env.example .env
  else
    echo -e "${BLUE}[*] Creating default .env configuration...${NC}"
    cat <<EOF > .env
PORT=8080
MONITOR_PORT=8081
KEY_BITS=256
STORAGE_DIR=/app/data/vault
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
EOF
  fi
fi

# Ensure MONITOR_PORT is in .env if missing
if ! grep -q "^MONITOR_PORT=" .env; then
  echo "MONITOR_PORT=8081" >> .env
fi

# 5. Ensure persistent storage directory exists with proper permissions
mkdir -p data/vault
chmod 777 data/vault || true

# 6. Build and launch container
echo -e "${BLUE}[*] Building and starting SecureVault container...${NC}"
$SUDO $COMPOSE_CMD up -d --build

# 7. Print success summary
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
PORT_VAL=$(grep -E "^PORT=" .env | cut -d= -f2 || echo "8080")
[ -z "$PORT_VAL" ] && PORT_VAL="8080"
MONITOR_PORT_VAL=$(grep -E "^MONITOR_PORT=" .env | cut -d= -f2 || echo "8081")
[ -z "$MONITOR_PORT_VAL" ] && MONITOR_PORT_VAL="8081"

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}  ✓ SecureVault & Dead Man Monitor are RUNNING!             ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "  🌐 Primary Vault App:   ${GREEN}http://${SERVER_IP}:${PORT_VAL}/${NC}"
echo -e "  ⏱️ Dead Man Monitor:    ${GREEN}http://${SERVER_IP}:${MONITOR_PORT_VAL}/${NC}"
echo -e "  📁 Persistent Data:     ./data/vault"
echo -e "  🛡️ Encryption:          256-Bit Dual-Key Split (AES-256-GCM)"
echo -e "\nUseful Commands:"
echo -e "  - View logs:   ${BLUE}$COMPOSE_CMD logs -f${NC}"
echo -e "  - Stop vault:  ${BLUE}$COMPOSE_CMD down${NC}"
echo -e "  - Restart:     ${BLUE}$COMPOSE_CMD restart${NC}"
echo -e "${GREEN}============================================================${NC}"
