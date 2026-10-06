import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import { Options } from './types';

export type RequestSettings = {
  proxy?: string;
  insecure?: boolean;
  ca?: Buffer;
};

export function requestSettings(options: Options): RequestSettings {
  return {
    proxy: options.proxy || process.env.http_proxy,
    insecure: options.insecure,
    ca: options.cacertbuf,
  };
}

type TlsSettings = Pick<tls.ConnectionOptions, 'rejectUnauthorized' | 'ca'>;

/**
 * GET a URL, optionally through an http:// or https:// proxy.
 * Plain http targets are sent to the proxy as absolute-form requests,
 * https targets are tunnelled through the proxy with CONNECT.
 */
export async function get(url: string, settings: RequestSettings = {}): Promise<http.IncomingMessage> {
  const target = new URL(url);
  const tlsSettings: TlsSettings = {
    rejectUnauthorized: !settings.insecure,
    ...(settings.ca ? { ca: [settings.ca] } : {}),
  };
  if (!settings.proxy) {
    return send(target.protocol === 'http:' ? http : https, url, tlsSettings);
  }

  const proxy = new URL(settings.proxy);
  if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
    throw new Error(`Unsupported proxy protocol: ${proxy.protocol} (only http: and https: are supported)`);
  }
  const proxyModule = proxy.protocol === 'https:' ? https : http;
  const proxyConnection = {
    host: unbracket(proxy.hostname),
    port: proxy.port || (proxy.protocol === 'https:' ? 443 : 80),
    ...(proxy.protocol === 'https:' ? tlsSettings : {}),
  };

  if (target.protocol === 'http:') {
    return send(proxyModule, {
      ...proxyConnection,
      path: url,
      headers: { host: target.host, ...proxyAuthorization(proxy) },
    });
  }

  const socket = await tunnel(proxyModule, proxyConnection, proxy, target);
  const servername = net.isIP(unbracket(target.hostname)) ? undefined : target.hostname;
  // No agent: Node only honours createConnection when the request has no agent.
  return send(https, url, {
    createConnection: () => tls.connect({ ...tlsSettings, socket, servername }),
  });
}

function tunnel(
  proxyModule: typeof http | typeof https,
  proxyConnection: https.RequestOptions,
  proxy: URL,
  target: URL,
): Promise<net.Socket> {
  const authority = `${target.hostname}:${target.port || 443}`;
  return new Promise((resolve, reject) => {
    const req = proxyModule.request({
      ...proxyConnection,
      method: 'CONNECT',
      path: authority,
      agent: false,
      headers: { host: authority, ...proxyAuthorization(proxy) },
    });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        return reject(new Error(`Proxy refused tunnel to ${authority}: HTTP ${res.statusCode} ${res.statusMessage}`));
      }
      resolve(socket);
    });
    req.on('error', reject);
    req.end();
  });
}

function send(
  module: typeof http | typeof https,
  url: string | https.RequestOptions,
  options: https.RequestOptions = {},
): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    const req = typeof url === 'string' ? module.get(url, options, resolve) : module.get(url, resolve);
    req.on('error', reject);
  });
}

function proxyAuthorization(proxy: URL): Record<string, string> {
  if (!proxy.username) return {};
  const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
  return { 'proxy-authorization': `Basic ${Buffer.from(credentials).toString('base64')}` };
}

function unbracket(hostname: string): string {
  return hostname.replace(/^\[(.*)\]$/, '$1');
}
