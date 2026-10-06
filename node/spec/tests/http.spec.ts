import { describe, it, before, after, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { get, requestSettings } from '../../lib/http';
import { loadrepository } from '../../lib/repo';
import { checkOSV } from '../../lib/depsdev';
import { options } from '../options';

const fixtures = path.join(__dirname, '..', 'fixtures', 'tls');
const key = fs.readFileSync(path.join(fixtures, 'test-key.pem'));
const cert = fs.readFileSync(path.join(fixtures, 'test-certificate.pem'));

type ProxyRequest = { method: string; url: string; host?: string; auth?: string };
type ProxyState = {
  log: ProxyRequest[];
  requireAuth: boolean;
  /** Open sockets, destroyed when the suite ends. */
  tunnels: Set<net.Socket>;
  /** Local ports of the proxy's connections to tunnel targets. */
  upstreamPorts: number[];
};

const credentials = { username: 'us er', password: 'p@ss:word' };
const expectedAuth = 'Basic ' + Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
const encodedCredentials = `${encodeURIComponent(credentials.username)}:${encodeURIComponent(credentials.password)}`;

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port)),
  );
}

function close(server: net.Server | http.Server | https.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    if ('closeAllConnections' in server) server.closeAllConnections();
  });
}

async function body(res: http.IncomingMessage): Promise<string> {
  let data = '';
  for await (const chunk of res) data += chunk;
  return data;
}

/** A forward proxy that records what it receives. Only tunnels to localhost, so tests never hit the network. */
function attachProxy(server: http.Server, state: ProxyState) {
  const { log, tunnels } = state;
  const authorized = (req: http.IncomingMessage) =>
    !state.requireAuth || req.headers['proxy-authorization'] === expectedAuth;

  server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
    log.push({ method: req.method!, url: req.url!, host: req.headers.host, auth: req.headers['proxy-authorization'] });
    if (!authorized(req)) {
      res.writeHead(407, 'Proxy Authentication Required');
      return res.end();
    }
    const upstream = http.request(req.url!, { method: req.method, headers: req.headers }, (r) => {
      res.writeHead(r.statusCode!, r.headers);
      r.pipe(res);
    });
    upstream.on('error', () => res.destroy());
    req.pipe(upstream);
  });

  server.on('connect', (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    log.push({ method: req.method!, url: req.url!, host: req.headers.host, auth: req.headers['proxy-authorization'] });
    tunnels.add(socket);
    socket.on('close', () => tunnels.delete(socket));
    if (!authorized(req)) return socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
    const [host, port] = req.url!.split(':');
    if (host !== 'localhost' && host !== '127.0.0.1') return socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    const upstream = net.connect(Number(port), '127.0.0.1', () => {
      state.upstreamPorts.push(upstream.localPort!);
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    tunnels.add(upstream);
    upstream.on('close', () => tunnels.delete(upstream));
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
}

describe('http', () => {
  const proxyState: ProxyState = { log: [], requireAuth: false, tunnels: new Set(), upstreamPorts: [] };
  const proxyLog = proxyState.log;
  let lastServername: string | false | undefined;
  let lastClientPort: number | undefined;
  const repositoryJson = JSON.stringify({
    jquery: {
      vulnerabilities: [
        { below: '1.9.0', severity: 'medium', cwe: ['CWE-79'], identifiers: { CVE: ['CVE-2012-6708'] }, info: [] },
      ],
      extractors: { filename: ['jquery-(§§version§§)\\.js'] },
    },
  });

  const httpTarget = http.createServer((req, res) => {
    if (req.url === '/repository.json') return res.end(repositoryJson);
    res.end(`http ${req.url}`);
  });
  const httpsTarget = https.createServer({ key, cert }, (req, res) => {
    lastServername = (req.socket as tls.TLSSocket & { servername?: string | false }).servername;
    lastClientPort = req.socket.remotePort;
    res.end(`https ${req.url}`);
  });
  const httpProxy = http.createServer();
  const httpsProxy = https.createServer({ key, cert });
  attachProxy(httpProxy, proxyState);
  attachProxy(httpsProxy, proxyState);

  /** The target must have been reached through the proxy's tunnel, not by a direct connection. */
  const assertTunnelled = () =>
    assert.ok(proxyState.upstreamPorts.includes(lastClientPort!), 'request bypassed the proxy tunnel');

  let httpPort: number, httpsPort: number, httpProxyPort: number, httpsProxyPort: number, closedPort: number;

  before(async () => {
    [httpPort, httpsPort, httpProxyPort, httpsProxyPort] = await Promise.all(
      [httpTarget, httpsTarget, httpProxy, httpsProxy].map(listen),
    );
    const unused = net.createServer();
    closedPort = await listen(unused);
    await close(unused);
  });

  after(async () => {
    proxyState.tunnels.forEach((socket) => socket.destroy());
    await Promise.all([httpTarget, httpsTarget, httpProxy, httpsProxy].map(close));
  });

  beforeEach(() => {
    proxyLog.length = 0;
    proxyState.upstreamPorts.length = 0;
    proxyState.requireAuth = false;
    lastServername = undefined;
    lastClientPort = undefined;
  });

  describe('without a proxy', () => {
    it('fetches http urls', async () => {
      const res = await get(`http://127.0.0.1:${httpPort}/plain`);
      assert.equal(await body(res), 'http /plain');
    });

    it('verifies https certificates against the provided ca', async () => {
      const res = await get(`https://localhost:${httpsPort}/secure`, { ca: cert });
      assert.equal(await body(res), 'https /secure');
    });

    it('rejects untrusted certificates', async () => {
      await assert.rejects(get(`https://localhost:${httpsPort}/secure`), /self-signed certificate/);
    });

    it('accepts untrusted certificates when insecure', async () => {
      const res = await get(`https://localhost:${httpsPort}/secure`, { insecure: true });
      assert.equal(await body(res), 'https /secure');
    });
  });

  describe('through an http proxy', () => {
    const proxy = () => `http://127.0.0.1:${httpProxyPort}`;

    it('sends http requests in absolute form', async () => {
      const url = `http://127.0.0.1:${httpPort}/plain?x=1`;
      const res = await get(url, { proxy: proxy() });

      assert.equal(await body(res), 'http /plain?x=1');
      assert.deepEqual(proxyLog, [{ method: 'GET', url, host: `127.0.0.1:${httpPort}`, auth: undefined }]);
    });

    it('tunnels https requests with CONNECT', async () => {
      const res = await get(`https://localhost:${httpsPort}/secure`, { proxy: proxy(), ca: cert });

      assert.equal(await body(res), 'https /secure');
      assertTunnelled();
      assert.deepEqual(proxyLog, [
        { method: 'CONNECT', url: `localhost:${httpsPort}`, host: `localhost:${httpsPort}`, auth: undefined },
      ]);
      assert.equal(lastServername, 'localhost');
    });

    it('does not send SNI for ip address targets', async () => {
      const res = await get(`https://127.0.0.1:${httpsPort}/secure`, { proxy: proxy(), ca: cert });

      assert.equal(await body(res), 'https /secure');
      assertTunnelled();
      assert.equal(lastServername, false);
    });

    it('verifies the target certificate end-to-end through the tunnel', async () => {
      await assert.rejects(get(`https://localhost:${httpsPort}/secure`, { proxy: proxy() }), /self-signed certificate/);
    });

    it('accepts untrusted target certificates through the tunnel when insecure', async () => {
      const res = await get(`https://localhost:${httpsPort}/secure`, { proxy: proxy(), insecure: true });
      assert.equal(await body(res), 'https /secure');
      assertTunnelled();
    });

    it('sends decoded basic credentials from the proxy url', async () => {
      proxyState.requireAuth = true;
      const withAuth = `http://${encodedCredentials}@127.0.0.1:${httpProxyPort}`;

      const tunnelled = await get(`https://localhost:${httpsPort}/secure`, { proxy: withAuth, ca: cert });
      assert.equal(await body(tunnelled), 'https /secure');
      assertTunnelled();
      const forwarded = await get(`http://127.0.0.1:${httpPort}/plain`, { proxy: withAuth });
      assert.equal(await body(forwarded), 'http /plain');

      assert.deepEqual(
        proxyLog.map((r) => [r.method, r.auth]),
        [
          ['CONNECT', expectedAuth],
          ['GET', expectedAuth],
        ],
      );
    });

    it('rejects when the proxy refuses the tunnel', async () => {
      proxyState.requireAuth = true;
      await assert.rejects(
        get(`https://localhost:${httpsPort}/secure`, { proxy: proxy(), ca: cert }),
        /Proxy refused tunnel to localhost:\d+: HTTP 407 Proxy Authentication Required/,
      );
    });

    it('returns the proxy response for refused http requests', async () => {
      proxyState.requireAuth = true;
      const res = await get(`http://127.0.0.1:${httpPort}/plain`, { proxy: proxy() });
      res.resume();
      assert.equal(res.statusCode, 407);
    });
  });

  describe('through an https proxy', () => {
    it('connects to the proxy over tls and tunnels https requests', async () => {
      const res = await get(`https://localhost:${httpsPort}/secure`, {
        proxy: `https://localhost:${httpsProxyPort}`,
        ca: cert,
      });

      assert.equal(await body(res), 'https /secure');
      assertTunnelled();
      assert.deepEqual(
        proxyLog.map((r) => [r.method, r.url]),
        [['CONNECT', `localhost:${httpsPort}`]],
      );
    });

    it('verifies the proxy certificate', async () => {
      await assert.rejects(
        get(`http://127.0.0.1:${httpPort}/plain`, { proxy: `https://localhost:${httpsProxyPort}` }),
        /self-signed certificate/,
      );
      assert.deepEqual(proxyLog, []);
    });
  });

  describe('errors', () => {
    it('rejects unsupported proxy protocols', async () => {
      await assert.rejects(
        get(`https://localhost:${httpsPort}/`, { proxy: 'socks5://127.0.0.1:1080' }),
        /Unsupported proxy protocol: socks5:/,
      );
    });

    it('rejects when the proxy is unreachable', async () => {
      await assert.rejects(
        get(`https://localhost:${httpsPort}/`, { proxy: `http://127.0.0.1:${closedPort}` }),
        /ECONNREFUSED/,
      );
    });
  });

  describe('requestSettings', () => {
    let savedEnv: string | undefined;
    before(() => {
      savedEnv = process.env.http_proxy;
    });
    after(() => {
      if (savedEnv === undefined) delete process.env.http_proxy;
      else process.env.http_proxy = savedEnv;
    });

    it('maps cli options', () => {
      delete process.env.http_proxy;
      const ca = Buffer.from('ca');
      assert.deepEqual(requestSettings({ ...options, proxy: 'http://p:1', insecure: true, cacertbuf: ca }), {
        proxy: 'http://p:1',
        insecure: true,
        ca,
      });
    });

    it('falls back to the http_proxy environment variable', () => {
      process.env.http_proxy = 'http://env:1';
      assert.equal(requestSettings(options).proxy, 'http://env:1');
      assert.equal(requestSettings({ ...options, proxy: 'http://cli:1' }).proxy, 'http://cli:1');
    });
  });

  describe('callers', () => {
    it('downloads the repository through the proxy', async () => {
      const url = `http://127.0.0.1:${httpPort}/repository.json`;
      const repo = await loadrepository(url, { ...options, proxy: `http://127.0.0.1:${httpProxyPort}` });

      assert.equal(repo.jquery.vulnerabilities[0].below, '1.9.0');
      assert.deepEqual(
        proxyLog.map((r) => [r.method, r.url]),
        [['GET', url]],
      );
    });

    it('sends OSV lookups through the proxy', async () => {
      const warnings: string[] = [];
      const result = await checkOSV('sample', '1.0.0', {
        ...options,
        proxy: `http://127.0.0.1:${httpProxyPort}`,
        log: { ...options.log, warn: (message: string) => warnings.push(message) },
      });

      assert.deepEqual(result, []);
      assert.deepEqual(
        proxyLog.map((r) => [r.method, r.url]),
        [['CONNECT', 'api.deps.dev:443']],
      );
      assert.match(warnings.join('\n'), /Proxy refused tunnel to api\.deps\.dev:443: HTTP 403/);
    });
  });
});
