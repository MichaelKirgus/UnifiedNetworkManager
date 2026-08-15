# Build context is the repository root (see docker-compose.yml) so that the
# shared openapi/ spec directory can be copied alongside the api/ source.
FROM node:20-alpine

WORKDIR /app

COPY api/package*.json ./api/
RUN cd api && npm install --legacy-peer-deps

COPY openapi ./openapi
COPY api ./api

RUN cd api && npm run build

WORKDIR /app/api
EXPOSE 3000

CMD ["npm", "start"]
