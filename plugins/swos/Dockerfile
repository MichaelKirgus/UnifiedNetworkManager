# Self-contained build context (./plugins/swos) — this plugin has no shared
# package dependencies, unlike snmp/lancom which need the repo root to build
# @unm/snmp-client. Digest auth is pure node:crypto; no extra apk packages.
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

EXPOSE 4007

CMD ["npm", "start"]
