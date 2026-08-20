FROM node:20-alpine

# net-snmp provides the daemon + standard MIBs (SNMPv2-MIB, IF-MIB under
# /usr/share/snmp/mibs); net-snmp-tools provides the `snmpwalk` CLI used for
# all SNMP queries. Vendor MIBs are expected in a mounted volume (see
# docker-compose.yml).
RUN apk add --no-cache net-snmp net-snmp-tools

WORKDIR /app

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

EXPOSE 4005

CMD ["npm", "start"]
