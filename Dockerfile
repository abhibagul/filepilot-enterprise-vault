# Use the official lightweight Node.js LTS image as base
FROM node:20-alpine

# Set working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json (if present)
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy the rest of the application files
COPY . .

# Expose port 8443 (default port for the service)
EXPOSE 8443

# Set production environment variables
ENV NODE_ENV=production
ENV PORT=8443
ENV VAULT_DATA_DIR=/app/data

# Start the microservice
CMD ["node", "server.cjs"]
