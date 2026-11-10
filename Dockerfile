FROM node:20-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=10000
ENV DATA_DIR=/app/data

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY server.js ./

RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 10000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 10000) + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
