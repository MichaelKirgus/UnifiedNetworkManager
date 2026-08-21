FROM node:20-alpine

# `ping` is not in the alpine base image — install it (iputils provides ping).
RUN apk add --no-cache iputils

WORKDIR /app

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

EXPOSE 4004

CMD ["npm", "start"]
