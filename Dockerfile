ARG NODE_VERSION=20-alpine

FROM node:${NODE_VERSION} AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM base AS builder
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY prisma ./prisma
RUN npx prisma generate
COPY src ./src
RUN npm run build

FROM node:${NODE_VERSION} AS runner
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY --from=builder /app/dist ./dist
COPY --from=deps /app/node_modules ./node_modules
COPY prisma ./prisma
COPY uploads ./uploads
EXPOSE 4001
CMD ["node", "dist/index.js"]
