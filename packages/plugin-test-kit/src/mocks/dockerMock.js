/**
 * @unm/plugin-test-kit — Docker Engine API mock appliance.
 *
 * Serves the read endpoints plugins/docker polls over plain TCP (transport
 * 'tcp'): GET /version, GET /containers/json, GET /images/json — with the same
 * realistic fixture data as the old scripts/mock-docker-daemon.cjs, but on an
 * ephemeral port and importable. Unknown paths answer 404 like a real daemon.
 */

import http from 'node:http';

const now = Date.now();

const containers = [
  {
    Id: 'a'.repeat(64),
    Names: ['/radius05'],
    Image: 'freeradius/freeradius-server:1.2.3',
    State: 'running',
    Status: 'Up 3 hours',
    StartedAt: new Date(now - 3 * 3600_000).toISOString(),
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
    StartedAt: new Date(now - 3 * 3600_000 + 60_000).toISOString(),
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
    StartedAt: new Date(now - 10 * 60_000).toISOString(),
    Ports: [{ IP: '0.0.0.0', PrivatePort: 6379, PublicPort: 6379, Type: 'tcp' }],
    Labels: {},
    NetworkSettings: { Networks: { bridge: { MacAddress: '02:42:ac:11:00:05', IPAMConfig: { IPv4Address: '172.17.0.5' } } } },
    Mounts: [{ Name: '', Source: '/tmp/redis-tmp', Destination: '/data', Mode: '', Type: 'tmpfs', RW: true }],
  },
];

const images = [
  { Id: `sha256:${'e'.repeat(64)}`, RepoTags: ['freeradius/freeradius-server:1.2.3'], RepoDigests: [`sha256:${'f'.repeat(64)}`], Created: Math.floor(now / 1000) - 86_400 * 30, Size: 182_000_000, VirtualSize: 182_000_000, Containers: 1 },
  { Id: `sha256:${'f'.repeat(64)}`, RepoTags: ['nginx:1.27-alpine', 'nginx:stable'], RepoDigests: [], Created: Math.floor(now / 1000) - 86_400 * 12, Size: 49_000_000, VirtualSize: 49_000_000, Containers: 1 },
  { Id: `sha256:${'a'.repeat(64)}`, RepoTags: ['redis:7.2'], RepoDigests: [], Created: Math.floor(now / 1000) - 86_400 * 90, Size: 118_000_000, VirtualSize: 118_000_000, Containers: 1 },
  { Id: `sha256:${'c'.repeat(64)}`, RepoTags: ['<none>:<none>'], RepoDigests: [], Created: Math.floor(now / 1000) - 86_400 * 3, Size: 7_000_000, VirtualSize: 7_000_000, Containers: 0 },
];

/**
 * @returns {Promise<{port:number, url:string, requests:Array, stop:()=>Promise<void>}>}
 */
export function startDockerDaemonMock() {
  const requests = [];
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, body: data });
        if (requests.length > 500) requests.shift();
        const send = (status, payload) => {
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(payload));
        };
        const url = new URL(req.url, 'http://127.0.0.1');
        if (url.pathname === '/version') {
          send(200, { Version: '27.3.1', ApiVersion: '1.47', MinAPIVersion: '1.12', Os: 'linux', Arch: 'aarch64' });
        } else if (url.pathname === '/containers/json') {
          send(200, containers);
        } else if (url.pathname === '/images/json') {
          send(200, images);
        } else {
          send(404, { message: `mock docker daemon: unknown path ${url.pathname}` });
        }
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        port,
        url: `http://127.0.0.1:${port}`,
        requests,
        stop: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}
