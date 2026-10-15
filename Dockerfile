FROM node:24-alpine AS builder

WORKDIR /app

COPY package.json pnpm-lock.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY . .
RUN npx prisma generate
RUN pnpm run build

FROM node:24-alpine AS runner
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./prisma.config.ts

ENV NODE_ENV=production
EXPOSE 3333

CMD ["node", "dist/server.js"]
