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

# Expose port 8200 (default port for the service)
EXPOSE 8200

# Set production environment variables
ENV NODE_ENV=production
ENV PORT=8200

# Start the microservice
CMD ["node", "server.cjs"]
