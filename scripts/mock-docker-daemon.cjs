#!/usr/bin/env node
/**
 * Mock Docker Engine daemon for the LIVE compose-network integration test of
 * plugins/docker (run inside a container on the UNM network, port 2375).
 * Serves GET /version + GET /containers/json?all=true with realistic data.
 */
const http = require('http');

const containers = [
  {
    Id: 'a'.repeat(64),
    Names: ['/radius05'],
    Image: 'freeradius/freeradius-server:1.2.3',
    State: 'running',
    Status: 'Up 3 hours',
    StartedAt: new Date(Date.now() - 3 * 3600_000).toISOString(),
    Ports: [{ IP: '0.0.0.0', PrivatePort: 1812, PublicPort: 1812, Type: 'udp' }],
    Labels: { 'com.docker.compose.project': 'radius', 'com.docker.compose.service': 'radius' },
    NetworkSettings: { Networks: { radius_default: { MacAddress: '02:42:ac:11:00:02', IPAMConfig: { IPv4Address: '172.17.0.2' } } } },
    Mounts: [
      { Name: '', Source: '/mnt/DATA/CONTAINER/RADIUS/DATA', Destination: '/etc/raddb', Mode: 'rw', Type: 'bind', RW: true },
      { Name: 'radius_logs', Source: '/var/lib/docker/volumes/radius_logs/_data', Destination: '/var/log/radius', Mode: 'z', Type: 'volume', RW: true },
    ],
  },
  {
    Id: 'b'.repeat(64),
    Names: ['/radius05-proxy'],
    Image: 'nginx:1.27-alpine',
    State: 'running',
    Status: 'Up 3 hours',
    StartedAt: new Date(Date.now() - 3 * 3600_000 + 60_000).toISOString(),
    Ports: [{ IP: '0.0.0.0', PrivatePort: 80, PublicPort: 8443, Type: 'tcp' }],
    Labels: { 'com.docker.compose.project': 'radius', 'com.docker.compose.service': 'proxy' },
    NetworkSettings: { Networks: { radius_default: { MacAddress: '02:42:ac:11:00:03', IPAMConfig: { IPv4Address: '172.17.0.3' } } } },
    Mounts: [{ Name: '', Source: '/mnt/DATA/CONTAINER/RADIUS/CONF', Destination: '/etc/nginx/conf.d', Mode: 'ro', Type: 'bind', RW: false }],
  },
  {
    Id: 'c'.repeat(64),
    Names: ['/standalone-redis'],
    Image: 'redis:7.2',
    State: 'running',
    Status: 'Up 10 minutes',
    StartedAt: new Date(Date.now() - 10 * 60_000).toISOString(),
    Ports: [{ IP: '0.0.0.0', PrivatePort: 6379, PublicPort: 6379, Type: 'tcp' }],
    Labels: {},
    NetworkSettings: { Networks: { bridge: { MacAddress: '02:42:ac:11:00:05', IPAMConfig: { IPv4Address: '172.17.0.5' } } } },
    Mounts: [{ Name: '', Source: '/tmp/redis-tmp', Destination: '/data', Mode: '', Type: 'tmpfs', RW: true }],
  },
];

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1`);
  if (url.pathname === '/version') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ Version: '27.3.1', ApiVersion: '1.47', MinAPIVersion: '1.12', Os: 'linux', Arch: 'aarch64' }));
  } else if (url.pathname === '/containers/json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(containers));
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: `mock docker daemon: unknown path ${url.pathname}` }));
  }
});

server.listen(2375, '0.0.0.0', () => console.log(`[mock-docker-daemon] listening on :2375 (${containers.length} containers)`));
