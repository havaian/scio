# Debian-based image: QVAC's native inference binaries need glibc (Alpine uses musl).
FROM node:22-slim AS build
WORKDIR /app
# WITH_QVAC=true installs the optional local-AI SDK (@qvac/sdk, about 2 GB). Default: skip it.
ARG WITH_QVAC=false
COPY package.json package-lock.json ./
RUN if [ "$WITH_QVAC" = "true" ]; then npm ci; else npm ci --omit=optional; fi
COPY tsconfig.json nest-cli.json ./
COPY src ./src
RUN npx nest build && npm prune --omit=dev $( [ "$WITH_QVAC" = "true" ] || echo --omit=optional )

FROM node:22-slim
WORKDIR /app
# WITH_BROWSER=true installs Chromium (about 300 MB) for bank login pages that need a real browser (JavaScript apps).
ARG WITH_BROWSER=true
RUN if [ "$WITH_BROWSER" = "true" ]; then apt-get update && apt-get install -y --no-install-recommends chromium fonts-dejavu-core && rm -rf /var/lib/apt/lists/*; fi
ENV NODE_ENV=production \
    CHROMIUM_PATH=/usr/bin/chromium \
    PORT=3000 \
    DB_FILE=/app/data/scio.sqlite \
    QVAC_MODEL_DIR=/app/models \
    NODE_NO_WARNINGS=1
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY config ./config
VOLUME ["/app/data", "/app/reports"]
EXPOSE 3000
CMD ["node", "dist/main.js"]
