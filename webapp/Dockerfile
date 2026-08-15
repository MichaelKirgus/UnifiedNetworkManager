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

EXPOSE 5173

CMD ["serve", "-s", "dist", "-l", "5173"]
