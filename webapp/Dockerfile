# Build tag baked in at image build time (CI sets UNM_BUILD_TAG; empty = local).
# The static bundle has no runtime process to report it, so the final stage writes
# a tiny manifest.json into dist/ that the webapp fetches from its own origin.
ARG UNM_BUILD_TAG=

FROM node:20-alpine AS build

WORKDIR /app

# VITE_API_URL is baked into the static bundle at build time (Vite replaces
# import.meta.env.VITE_* references during `vite build`), so it must be
# supplied as a build arg rather than a runtime container environment
# variable, which would have no effect on the already-built assets.
ARG VITE_API_URL=http://localhost:3000/v1
ENV VITE_API_URL=${VITE_API_URL}

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

FROM node:20-alpine

WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist
# Bake the build tag into a manifest the UI can read (same origin, no API needed).
ARG UNM_BUILD_TAG=
RUN node -e "require('fs').writeFileSync('/app/dist/manifest.json', JSON.stringify({ buildTag: process.env.UNM_BUILD_TAG || '' }))"

EXPOSE 5173

CMD ["serve", "-s", "dist", "-l", "5173"]
