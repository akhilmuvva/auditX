FROM node:20-alpine

# Install system dependencies (for python, build-base, and toolchains)
RUN apk add --no-cache python3 py3-pip build-base git bash curl

# Install Slither and Mythril via pip (requires python3)
# Note: In a production environment, mythril might require more complex setup (solc etc)
RUN pip3 install --no-cache-dir slither-analyzer mythril --break-system-packages

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci

# Install Surya globally
RUN npm install -g surya

# Copy application code
COPY . .

# Build dashboard (if necessary)
RUN cd dashboard && npm ci && npm run build

# Expose ports for SSE server and Dashboard
EXPOSE 3000
EXPOSE 5173

# Entrypoint
CMD ["node", "auditx.js"]
