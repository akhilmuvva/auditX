#!/usr/bin/env bash
# ==============================================================================
# AuditX — Oracle Cloud Free Tier (Arm64/Ubuntu) Automated Deployment Script
# 
# Usage:
#   curl -sSL https://raw.githubusercontent.com/akhilmuvva/auditX/main/scripts/setup_oracle.sh | bash
# ==============================================================================

set -euo pipefail

# Text styling variables
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ─── 1. Beautiful Header Banner ───────────────────────────────────────────────
clear
echo -e "${CYAN}============================================================"
echo -e "         AuditX — Oracle Cloud Automated Provisioner"
echo -e "         Stack: Docker · NodeJS · Python · Security"
echo -e "============================================================${NC}\n"

echo -e "${YELLOW}[1/6] Upgrading OS package lists...${NC}"
sudo apt-get update -y && sudo apt-get upgrade -y

# ─── 2. Local Host Firewall Configurations (iptables) ─────────────────────────
echo -e "\n${YELLOW}[2/6] Configuring persistent firewall rules for Port 3000...${NC}"
# Insert accept rule on Port 3000 at line 6 of INPUT chain (before default drop rules)
sudo iptables -I INPUT 6 -p tcp --dport 3000 -m state --state NEW -j ACCEPT

# Save persistently across server reboots
echo -e "${CYAN}Saving firewall tables...${NC}"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent
sudo netfilter-persistent save
sudo netfilter-persistent reload
echo -e "${GREEN}✓ Local VM Firewall updated. Port 3000 is open.${NC}"

# ─── 3. Installing Docker & Docker Compose ────────────────────────────────────
echo -e "\n${YELLOW}[3/6] Installing Docker Engine & Compose plugin...${NC}"
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes

# Set up Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker daemon
sudo systemctl enable docker
sudo systemctl start docker

# Add ubuntu user to docker group to run without sudo
sudo usermod -aG docker ubuntu || true
echo -e "${GREEN}✓ Docker Engine successfully installed.${NC}"

# ─── 4. Cloning AuditX Repository ─────────────────────────────────────────────
echo -e "\n${YELLOW}[4/6] Cloning AuditX Repository into /home/ubuntu/auditX...${NC}"
cd /home/ubuntu
if [ -d "auditX" ]; then
  echo -e "${CYAN}AuditX folder already exists, pulling latest changes...${NC}"
  cd auditX
  git pull origin main
else
  git clone https://github.com/akhilmuvva/auditX.git
  cd auditX
fi
echo -e "${GREEN}✓ Repository cloned.${NC}"

# ─── 5. Interactive Environment Variables Configuration ────────────────────────
echo -e "\n${YELLOW}[5/6] Configuring Production Environment (.env)...${NC}"
ENV_FILE=".env"

# Prompt user for credentials (with pre-existing checks or defaults)
read -p "Enter Base Sepolia Private Key (32-byte hex): " PVT_KEY
read -p "Enter Anthropic API Key (or press enter to skip): " AI_KEY

cat <<EOF > "$ENV_FILE"
PRIVATE_KEY=${PVT_KEY}
BASE_SEPOLIA_RPC=https://sepolia.base.org
SUBGRAPH_URL=https://api.studio.thegraph.com/query/auditx/v1
CERAMIC_URL=https://ceramic-clay.3boxlabs.com
ANTHROPIC_API_KEY=${AI_KEY:-your_anthropic_api_key_here}
EOF

echo -e "${GREEN}✓ Production environment .env variables saved.${NC}"

# ─── 6. Docker Container Orchestration ────────────────────────────────────────
echo -e "\n${YELLOW}[6/6] Building and running AuditX Security Engine...${NC}"
# Run build and daemon startup only for backend-engine
sudo docker compose up --build -d auditx-engine

echo -e "\n${GREEN}============================================================"
echo -e "🎉 AuditX Automated Deployment Completed Successfully!"
echo -e "============================================================${NC}"
echo -e "📡 API Backend running on:  ${CYAN}http://$(curl -s ifconfig.me):3000${NC}"
echo -e "🔒 Port 3000 status:       ${GREEN}OPEN & ACTIVE${NC}"
echo -e "📂 Cache Directory:        ${CYAN}/home/ubuntu/auditX/cache/${NC}"
echo -e "\n${YELLOW}Next Step:${NC} Connect your Vercel Dashboard project by setting"
echo -e "the env variable ${CYAN}VITE_API_URL${NC} to ${GREEN}http://$(curl -s ifconfig.me):3000${NC}."
echo -e "============================================================\n"
