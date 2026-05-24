FROM node:20-slim

# Install system dependencies (build tools, python3, git, and curl)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pin compatible setuptools and install Slither + Mythril
RUN pip3 install --upgrade pip \
    && pip3 install "setuptools<60" \
    && pip3 install slither-analyzer mythril --break-system-packages

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci

# Copy application source code
COPY . .

# Compile TypeScript code
RUN npm run build

# Install Surya globally
RUN npm install -g surya

# Expose backend API and SIEM server port
EXPOSE 3000

# Start AuditX API & SIEM server
CMD ["node", "dist/src/cli.js", "server"]
