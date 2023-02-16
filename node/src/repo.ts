import * as fs from "fs";
import * as path from "path";
import { forwardEvent as forward } from "./utils";
import * as http from "http";
import * as https from "https";
import * as retire from "./retire";
import * as URL from "url";
import ProxyAgent from "proxy-agent";
import { EventEmitter as Emitter } from "events";
import { Options, Repository } from "./types";

function loadJson(url: string, options: Options): Emitter {
  const events = new Emitter();
  options.log.info('Downloading ' + url + ' ...');
  const reqOptions: https.RequestOptions = { ...URL.parse(url), method: 'GET' };
  const proxyUri = options.proxy || process.env.http_proxy;
  if (proxyUri) {
    reqOptions.agent = new ProxyAgent(proxyUri);
  }
  if (options.insecure) {
    reqOptions.rejectUnauthorized = false;
  }
  if (options.cacertbuf) {
    reqOptions.ca = [ options.cacertbuf ];
  }
  const req = (url.startsWith("http:") ? http : https).get(reqOptions, function (res) {
    if (res.statusCode != 200) return events.emit('stop', 'Error downloading: ' + url + ": HTTP " + res.statusCode + " " + res.statusMessage);
    const data: Buffer[] = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {
        let d = Buffer.concat(data).toString();
        d = options.process ? options.process(d) : d;
        events.emit('done', JSON.parse(d));
    });
  });
  req.on('error', e => events.emit('stop', 'Error downloading: ' + url + ": " + e.toString()));
  req.end();
  return events;
}

function loadJsonFromFile(file: string, options: Options): Emitter {
  options.log.debug('Reading ' + file + ' ...');
  const events = new Emitter();
  fs.readFile(file, { encoding : 'utf8'}, function(err, data) {
    if (err) { return events.emit('stop', err.toString()); }
    data = options.process ? options.process(data) : data;
    const obj = JSON.parse(data);
    events.emit('done', obj);
  });
  return events;
}

function loadFromCache(url: string, cachedir: string, options: Options) {
  const cacheIndex = path.resolve(cachedir, 'index.json');
  if (!fs.existsSync(cachedir)) fs.mkdirSync(cachedir);
  const cache = fs.existsSync(cacheIndex) ? JSON.parse(fs.readFileSync(cacheIndex, "utf-8")) : {};
  const now = new Date().getTime();
  if (cache[url]) {
    if (now - cache[url].date < 60*60*1000) {
      options.log.info('Loading from cache: ' + url);
      return loadJsonFromFile(path.resolve(cachedir, cache[url].file), options);
    } else {
      if (fs.existsSync(path.resolve(cachedir, cache[url].date + '.json'))) {
        try {
          fs.unlinkSync(path.resolve(cachedir, cache[url].date + '.json'));
        } catch (error) {
          if (error != null && typeof error == "object" && "code" in error && error.code !== 'ENOENT') {
            throw error;
          } else {
            console.warn("Could not delete cache. Ignore this error if you are running multiple retire.js in parallel");
          }
        }
      }
    }
  }
  const events = new Emitter();
  loadJson(url, options).on('done', function(data) {
    cache[url] = { date : now, file : now + '.json' };
    fs.writeFileSync(path.resolve(cachedir, cache[url].file), JSON.stringify(data), { encoding : 'utf8' });
    fs.writeFileSync(cacheIndex, JSON.stringify(cache), { encoding : 'utf8' });
    events.emit('done', data);
  }).on('stop', forward(events, 'stop'));
  return events;
}

export function asbowerrepo(jsRepo: Repository) {
  const result = {} as Repository;
  Object.keys(jsRepo).map(function(k) {
    ([jsRepo[k].bowername || k]).map((b: string) => {
      result[b] = result[b] || { vulnerabilities: [] };
      result[b].vulnerabilities = result[b].vulnerabilities.concat(jsRepo[k].vulnerabilities);
    });
  });
  return result;
};

export function loadrepository(repoUrl: string, options: Options): Emitter {
  //options = utils.extend(options, { process : retire.replaceVersion });
  options = {...options, process : retire.replaceVersion };
  if (options.nocache) {
    return loadJson(repoUrl, options);
  }
  return loadFromCache(repoUrl, options.cachedir, options);
};

export function loadrepositoryFromFile(filepath: string, options: Options): Emitter {
  options = {...options, process : retire.replaceVersion };
  return loadJsonFromFile(filepath, options);
};
