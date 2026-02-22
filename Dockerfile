# Stage 1: Build the frontend assets
FROM node:18-alpine AS builder
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application source code
COPY . .

# Build the React application
RUN npm run build

# Stage 2: Create the final production image
FROM node:18-alpine
WORKDIR /app

# Set production environment
ENV NODE_ENV=production

# Copy package files and install only production dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy the built frontend assets from the builder stage
COPY --from=builder /app/dist ./dist

# Copy the server and other necessary files
COPY server.ts . 
COPY src/lib src/lib

# Expose the port the app runs on
EXPOSE 3000

# Command to run the application
CMD ["npm", "run", "start:prod"]
