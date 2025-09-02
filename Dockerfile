# Production multi-stage Dockerfile for Next.js
# Builder
FROM node:18-alpine AS builder
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm install --silent

# Copy sources and build
COPY . .
RUN npm run build

# Runner
FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Copy only what we need from builder
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/next.config.js ./next.config.js

EXPOSE 3000
# Install curl for healthchecks
RUN apk add --no-cache curl
# Use Next's start command in production
CMD ["npm", "start"]
