import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as https from 'https';
import * as retire from './retire';
import * as URL from 'url';
import { ProxyAgent } from 'proxy-agent';
import { Options, Repository } from './types';
import * as z from 'zod';
import { severityLevels } from './types';


export function validateRepository(
  repo: Repository,
  replacer?: Options['process'],
): z.SafeParseReturnType<unknown, Repository> {
  const keys = Object.keys(severityLevels) as [keyof typeof severityLevels];
  const versionValidator = z.string().regex(/^[\d.]+([a-zA-Z\d.-]+)?$/);
  const numericString = z.string().regex(/^[\d]+$/);
  const vulnValidator = z
    .object({
      below: versionValidator,
      atOrAbove: versionValidator.optional(),
      severity: z.enum(keys),
      cwe: z.array(z.string().regex(/^CWE-[0-9]+$/)).min(1),
      identifiers: z
        .object({
          CVE: z.array(z.string().regex(/^CVE-[0-9X-]+$/)).optional(),
          bug: z
            .string()
            .regex(/^[a-z0-9-]+$/i)
            .optional(),
          issue: numericString.optional(),
          summary: z.string().min(3).optional(),
          githubID: z
            .string()
            .regex(/^GHSA[A-Z0-9-]+$/i)
            .optional(),
          osvdb: z.array(numericString).optional(),
          gist: z
            .string()
            .regex(/^[a-z0-9-]+\/[a-f0-9]+$/i)
            .optional(),
          tenable: numericString.optional(),
          blog: z
            .string()
            .min(10)
            .regex(/^[:a-z0-9/-]+$/)
            .optional(),
          release: z.string().min(5).optional(),
          PR: numericString.optional(),
          retid: z
            .string()
            .regex(/^[\d]+$/)
            .optional(),
        })
        .strict()
        .superRefine((o, ctx) => {
          if (Object.keys(o).filter((k) => k != 'summary').length == 0)
            ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Must have at least one identifier' });
          const ids = Object.values(o)
            .map((x) => (Array.isArray(x) ? x : [x]))
            .reduce((a, b) => a.concat(b), []).length;
          if (ids == 0) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Must have at least one identifier' });
        }),
      info: z.array(z.string().regex(/^https?:\/\/.+/)),
    })
    .strict();
  const regexValidator = z.string().superRefine((s, ctx) => {
    if (ctx.path[0] == 'dont check') return;
    try {
      new RegExp(s);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Invalid regex: ' + s,
      });
    }
    if (s.includes('[]')) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Regex must not contain []: ' + s });
    if (s.includes('{}')) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Regex must not contain {}: ' + s });
    [/.*[^\\]\{[^0-9,\\]\}.*/, /[^,0-9\\]\}/, /[^\\]\{[^,0-9]/].forEach((r) => {
      if (r.test(s))
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'There is something odd with this regex: ' + s });
    });
    let versionMatcher = '§§version§§';
    if (replacer) versionMatcher = JSON.parse(`"${replacer(versionMatcher)}"`);
    const versionIndex = s.indexOf(versionMatcher);
    if (versionIndex == -1 || (versionIndex > 0 && s.substring(versionIndex - 1, versionIndex) == '\\')) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Regex must contain (§§version§§): ' + s });
    } else if (s.replace(/\(\?:/g, '').replace(/\\\(/g, '').split(/\(/)[1].indexOf(versionMatcher) != 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'Regex must contain (§§version§§) as first capture group: ' + s.replace(/\(\?:/g, '').replace(/\\\(/g, ''),
      });
    }
  });
  const replaceValidator = z
    .string()
    .regex(/^\/(.*[^\\])\/([^/]+)\/$/, 'RegExp error - should be on format "/search/replacement/"');

  const validator = z.record(
    z
      .object({
        bowername: z.array(z.string().regex(/^[a-z0-9.-]+$/i)).optional(),
        basePurl: z
          .string()
          .regex(/^pkg:[a-z0-9%.-/]+$/i)
          .optional(),
        npmname: z
          .string()
          .regex(/^[a-z0-9.-]+$/i)
          .optional(),
        vulnerabilities: z.array(vulnValidator),
        extractors: z
          .object({
            func: z.array(z.string().min(5)).optional(),
            uri: z.array(regexValidator).optional(),
            filename: z.array(regexValidator).optional(),
            filecontent: z.array(regexValidator).optional(),
            filecontentreplace: z.array(replaceValidator).optional(),
            hashes: z.record(z.string().regex(/^[a-f0-9]+$/i), versionValidator).optional(),
            ast: z.array(z.string()).optional(),
          })
          .strict(),
        licenses: z
          .array(
            z
              .string()
              .regex(
                /(\([A-Za-z\-0-9.]+( OR [A-Za-z\-0-9.]+)+\)|[A-Za-z\-0-9.]+) >=[0-9.]+( <[0-9.]+)?(;>=[0-9.]+( <[0-9.]+)?)*/,
              ),
          )
          .optional(),
      })
      .strict(),
  );
  return validator.safeParse(repo);
}
function formatValidationError(error: z.ZodError) {
  return JSON.stringify(
    error.format(),
    (key, value) => (Array.isArray(value) && value.length === 0 ? undefined : value),
    2,
  );
}

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
        const json = JSON.parse(d);
        const vresult = validateRepository(json, options.process);
        if (vresult.success) {
          resolve(json);
        } else {
          reject(`Invalid repository from ${url}: ${formatValidationError(vresult.error)}`);
        }
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
      const json = JSON.parse(data);
      const vresult = validateRepository(json, options.process);
      if (vresult.success) {
        resolve(json);
      } else {
        reject(`Invalid repository from ${file}: ${formatValidationError(vresult.error)}`);
      }
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
    (jsRepo[k].bowername || [k]).map((b: string) => {
      result[b] = result[b] || { vulnerabilities: [] };
      result[b].vulnerabilities = result[b].vulnerabilities.concat(jsRepo[k].vulnerabilities);
    });
  });
  return result;
}

export async function loadrepository(repoUrl: string, options: Options): Promise<Repository> {
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
