# Stage 1: Build the frontend
FROM node:20-slim AS builder
WORKDIR /app

# Install build dependencies for native modules (better-sqlite3)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Production environment
FROM node:20-slim
WORKDIR /app

# Install runtime dependencies for native modules (better-sqlite3)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# IMPORTANT: Install ALL dependencies first so 'tsx' is available
# We set NODE_ENV=production AFTER this step
RUN npm install

# Now set production environment
ENV NODE_ENV=production

# Copy built assets from builder
COPY --from=builder /app/dist ./dist
# Copy source files needed for the server
COPY server.ts .
COPY tsconfig.json .
COPY src/lib ./src/lib
COPY index.html .

# Create a directory for the database
RUN mkdir -p /app/data && chmod 777 /app/data
ENV DB_PATH=/app/data/secrets.db

EXPOSE 3000

# Use npx tsx to run the server directly
CMD ["npx", "tsx", "server.ts"]
