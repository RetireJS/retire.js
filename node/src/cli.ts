#!/usr/bin/env node

import * as utils from './utils';
import { program } from 'commander';

import * as retire from './retire';
import * as repo from './repo';
import * as resolve from './resolve';
import * as scanner from './scanner';
import * as reporting from './reporting';
import os from 'os';
import path from 'path';
import fs from 'fs';
import colors from 'ansi-colors';
import { EventEmitter } from 'events';
import { Finding, Options, severityLevels } from './types';
import * as z from 'zod';

const events = new EventEmitter();
let failProcess = false;
const defaultIgnoreFiles = ['.retireignore', '.retireignore.json'];

if (process.argv.includes('--node') || process.argv.includes('-n')) {
  console.log('Error: retire.js no longer supports scanning node packages. Use npm audit instead.');
  process.exit(1);
}

/*
 * Parse command line flags.
 */
const prg = program
  .version(retire.version)
  .option('-v, --verbose', 'Show identified files (by default only vulnerable files are shown)')
  .option('-c, --nocache', "Don't use local cache")
  .option('--jspath <path>', 'Folder to scan for javascript files (deprecated)')
  .option('--path <path>', 'Folder to scan for javascript files')
  .option(
    '--jsrepo <path|url>',
    "Local or internal version of repo. Can be multiple comma separated. Default: 'central')",
  )
  .option('--cachedir <path>', 'Path to use for local cache instead of /tmp/.retire-cache')
  .option('--proxy <url>', 'Proxy url (http://some.host:8080)')
  .option(
    '--outputformat <format>',
    'Valid formats: text, json, jsonsimple, depcheck (experimental), cyclonedx, cyclonedxJSON and cyclonedxJSON1_6',
  )
  .option('--outputpath <path>', 'File to which output should be written')
  .option('--ignore <paths>', 'Comma delimited list of paths to ignore')
  .option('--ignorefile <path>', 'Custom ignore file, defaults to .retireignore / .retireignore.json')
  .option(
    '--severity <level>',
    'Specify the bug severity level from which the process fails. Allowed levels none, low, medium, high, critical. Default: none',
  )
  .option('--exitwith <code>', 'Custom exit code (default: 13) when vulnerabilities are found')
  .option('--colors', 'Enable color output (console output only)')
  .option(
    '--insecure',
    'Enable fetching remote jsrepo/noderepo files from hosts using an insecure or self-signed SSL (TLS) certificate',
  )
  .option('--ext <extensions>', 'Comma separated list of file extensions for JavaScript files. The default is "js"')
  .option(
    '--cacert <path>',
    'Use the specified certificate file to verify the peer used for fetching remote jsrepo/noderepo files',
  )
  .option('--includeOsv', 'Include OSV advisories in the output')
  .option('--deep', 'Deep scan (slower and experimental)')
  .parse()
  .opts();

const colorwarn = prg.colors ? colors.red : (x: string) => x;
const jsrepolocation: string[] = (prg.jsrepo ?? "'central'")
  .split(',')
  .map((x: string) =>
    x === "'central'"
      ? 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json'
      : x,
  );

const ignorefile = prg.ignoreFile ?? defaultIgnoreFiles.filter((x) => fs.existsSync(x))[0];

const scanpath = prg.path ?? prg.jspath ?? '.';

const log = reporting.open({
  colors: !!prg.colors,
  colorwarn,
  jsRepo: jsrepolocation.join(', '),
  outputformat: prg.outputformat,
  outputpath: prg.outputpath,
  path: scanpath,
  verbose: !!prg.verbose,
});

const severity = prg.severity ?? 'none';
if (!(severity in severityLevels)) {
  exitWithError(
    `Error: Invalid severity level (${severity}). Valid levels are: ${Object.keys(severityLevels).join(', ')}`,
  );
}

const config: Options = {
  path: scanpath,
  ignore: {
    paths: [],
    pathsAsString: prg.ignore?.split(',')?.map((x: string) => path.resolve(x)) ?? [],
    descriptors: [],
  },
  colorwarn,
  nocache: prg.nocache ? true : false,
  cachedir: prg.cachedir ?? path.resolve(os.tmpdir(), '.retire-cache/'),
  log: log,
  severity: severity,
  exitwith: prg.exitwith ?? 13,
  includeOsv: !!prg.includeOsv,
  verbose: !!prg.verbose,
  proxy: prg.proxy,
  deep: !!prg.deep,
  ext: prg.ext ?? 'js',
};

log.info(`retire.js v${retire.version}`);

function exitWithError(msg: string) {
  log.error(config.colorwarn(msg));
  process.exitCode = 1;
  log.close();
}

if (prg.cacert) {
  if (!fs.existsSync(prg.cacert)) {
    exitWithError(`Error: Could not read cacert file: ${prg.cacert}`);
  }
  config.cacertbuf = fs.readFileSync(prg.cacert);
}

const ignoreFileParser = z.array(
  z
    .object({
      justification: z.string(),
    })
    .and(
      z
        .object({
          path: z.string(),
        })
        .or(
          z.object({
            component: z.string(),
            version: z.string().optional(),
            identifiers: z.record(z.string(), z.string()).optional(),
          }),
        ),
    ),
);

if (ignorefile) {
  if (!fs.existsSync(ignorefile)) {
    exitWithError(`Error: Could not read ignore file: ${ignorefile}`);
  }
  if (ignorefile.substr(-5) === '.json') {
    try {
      config.ignore.descriptors = ignoreFileParser.parse(JSON.parse(fs.readFileSync(ignorefile, 'utf-8')));
    } catch (e) {
      exitWithError(`Error: Invalid ignore file: ${ignorefile}`);
    }
    const ignoredPaths =
      config.ignore.descriptors
        ?.map((x) => ('path' in x ? x.path : undefined))
        ?.filter((x): x is string => x != undefined) ?? [];
    config.ignore.pathsAsString = config.ignore.pathsAsString.concat(ignoredPaths);
  } else {
    const lines = fs
      .readFileSync(ignorefile, 'utf-8')
      .split(/\r\n|\n/g)
      .filter((e) => e !== '');
    const ignored = lines.map((e) => {
      return e[0] === '@' ? e.slice(1) : path.resolve(e);
    });
    config.ignore.pathsAsString = config.ignore.pathsAsString.concat(ignored);
  }
}
config.ignore.paths = config.ignore.pathsAsString
  .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
  .map((p) => p.replace(/[*]{1,2}/g, (a) => (a.length == 2 ? '.*' : '[^/]*')))
  .map((s) => new RegExp(s));

scanner.on('vulnerable-dependency-found', (result: Finding) => {
  const levels = result.results.map((r) => {
    return r.vulnerabilities
      ? r.vulnerabilities.map((v) => {
          return severityLevels[v.severity ?? 'critical'];
        })
      : [];
  });
  const severity = utils.flatten(levels).reduce((x, y) => (x > y ? x : y));
  if (severity >= severityLevels[config.severity]) {
    failProcess = true;
  }
});

scanner.on('vulnerable-dependency-found', log.logVulnerableDependency);
scanner.on('dependency-found', log.logDependency);

events.on('scan-done', () => {
  process.exitCode = failProcess ? config.exitwith : 0;
  log.close();
});

process.on('uncaughtException', (err, ...rest) => {
  console.warn('Exception caught: ', err, rest);
  console.warn(err.stack);
  process.exit(1);
});

events.on('stop', (err) => {
  exitWithError(err);
});

Promise.all(
  jsrepolocation.map((jsr) =>
    jsr.match(/^https?:\/\//) ? repo.loadrepository(jsr, config) : repo.loadrepositoryFromFile(jsr, config),
  ),
)
  .then((jsRepos) => {
    resolve
      .scanJsFiles(config.path, config)
      .on('jsfile', (file) => {
        jsRepos.forEach((jsRepo) => {
          scanner.scanJsFile(file, jsRepo, config);
        });
      })
      .on('bowerfile', (bowerfile) => {
        jsRepos.forEach((jsRepo) => {
          const bowerRepo = repo.asbowerrepo(jsRepo);
          scanner.scanBowerFile(bowerfile, bowerRepo, config);
        });
      })
      .on('end', () => {
        events.emit('scan-done');
      });
  })
  .catch((e) => events.emit('stop', e));
