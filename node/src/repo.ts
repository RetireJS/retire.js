import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as https from 'https';
import * as retire from './retire';
import * as URL from 'url';
import { ProxyAgent } from 'proxy-agent';
import { Options, Repository } from './types';

async function loadJson<T>(url: string, options: Options): Promise<T> {
  return new Promise((resolve, reject) => {
    options.log.info('Downloading ' + url + ' ...');
    const reqOptions: https.RequestOptions = { ...URL.parse(url), method: 'GET' };
    const proxyUri = options.proxy || process.env.http_proxy;
    if (proxyUri) {
      reqOptions.agent = new ProxyAgent({
        getProxyForUrl: () => proxyUri,
      });
    }
    if (options.insecure) {
      reqOptions.rejectUnauthorized = false;
    }
    if (options.cacertbuf) {
      reqOptions.ca = [options.cacertbuf];
    }
    const req = (url.startsWith('http:') ? http : https).get(reqOptions, (res) => {
      if (res.statusCode != 200)
        return reject(`Error downloading: ${url}: HTTP ${res.statusCode} ${res.statusMessage}`);
      const data: Buffer[] = [];
      res.on('data', (c) => data.push(c));
      res.on('end', () => {
        let d = Buffer.concat(data).toString();
        d = options.process ? options.process(d) : d;
        resolve(JSON.parse(d));
      });
    });
    req.on('error', (e) => reject(`Error downloading: ${url}: ${e}`));
    req.end();
  });
}

async function loadJsonFromFile<T>(file: string, options: Options): Promise<T> {
  options.log.debug('Reading ' + file + ' ...');
  return new Promise((resolve, reject) => {
    fs.readFile(file, { encoding: 'utf8' }, (err, data) => {
      if (err) {
        return reject(err.toString());
      }
      data = options.process ? options.process(data) : data;
      resolve(JSON.parse(data));
    });
  });
}

async function loadFromCache<T>(url: string, cachedir: string, options: Options): Promise<T> {
  const cacheIndex = path.resolve(cachedir, 'index.json');
  if (!fs.existsSync(cachedir)) fs.mkdirSync(cachedir);
  const cache = fs.existsSync(cacheIndex) ? JSON.parse(fs.readFileSync(cacheIndex, 'utf-8')) : {};
  const now = new Date().getTime();
  if (cache[url]) {
    if (now - cache[url].date < 60 * 60 * 1000) {
      options.log.info('Loading from cache: ' + url);
      return loadJsonFromFile(path.resolve(cachedir, cache[url].file), options);
    } else {
      if (fs.existsSync(path.resolve(cachedir, cache[url].date + '.json'))) {
        try {
          fs.unlinkSync(path.resolve(cachedir, cache[url].date + '.json'));
        } catch (error) {
          if (error != null && typeof error == 'object' && 'code' in error && error.code !== 'ENOENT') {
            throw error;
          } else {
            console.warn('Could not delete cache. Ignore this error if you are running multiple retire.js in parallel');
          }
        }
      }
    }
  }
  const data = await loadJson<T>(url, options);
  cache[url] = { date: now, file: now + '.json' };
  fs.writeFileSync(path.resolve(cachedir, cache[url].file), JSON.stringify(data), { encoding: 'utf8' });
  fs.writeFileSync(cacheIndex, JSON.stringify(cache), { encoding: 'utf8' });
  return data;
}

export function asbowerrepo(jsRepo: Repository) {
  const result = {} as Repository;
  Object.keys(jsRepo).map((k) => {
    [jsRepo[k].bowername || k].map((b: string) => {
      result[b] = result[b] || { vulnerabilities: [] };
      result[b].vulnerabilities = result[b].vulnerabilities.concat(jsRepo[k].vulnerabilities);
    });
  });
  return result;
}

export async function loadrepository(repoUrl: string, options: Options): Promise<Repository> {
  //options = utils.extend(options, { process : retire.replaceVersion });
  options = { ...options, process: retire.replaceVersion };
  if (options.nocache) {
    return await loadJson(repoUrl, options);
  }
  return await loadFromCache(repoUrl, options.cachedir, options);
}

export async function loadrepositoryFromFile(filepath: string, options: Options): Promise<Repository> {
  options = { ...options, process: retire.replaceVersion };
  return await loadJsonFromFile(filepath, options);
}
