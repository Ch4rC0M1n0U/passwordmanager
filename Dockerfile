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
# Ensure optional files/dirs exist so later COPY in runner stage won't fail on platforms
RUN if [ ! -d "./public" ]; then mkdir -p ./public; fi
RUN if [ ! -f "./next.config.js" ]; then printf "module.exports = {}\n" > ./next.config.js; fi

# Runner
FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Copy only what we need from builder
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
# Safely copy optional public/ and next.config.js if they exist in builder
RUN if [ -d "/app/public" ]; then cp -R /app/public ./public; fi
RUN if [ -f "/app/next.config.js" ]; then cp /app/next.config.js ./next.config.js; fi

EXPOSE 3000
# Install curl for healthchecks
RUN apk add --no-cache curl
# Use Next's start command in production
CMD ["npm", "start"]
