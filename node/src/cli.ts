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
import { Finding, Options, severityLevels, severityParser } from './types';
import { parseIgnoreFile } from './parseIgnoreFile';

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
    'Valid formats: text, json, jsonsimple, depcheck (experimental), cyclonedx, cyclonedxJSON, cyclonedxJSON1_6, cyclonedxJSON1_6_VEX, cyclonedxJSON1_7, cyclonedxJSON1_7_VEX',
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

const red = (x: string) => `\u001b[31m${x}\u001b[39m`;
const colorwarn = prg.colors ? red : (x: string) => x;
const jsrepolocation: string[] = (prg.jsrepo ?? "'central'")
  .split(',')
  .map((x: string) =>
    x === "'central'"
      ? 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json'
      : x,
  );

const ignorefile = prg.ignorefile ?? defaultIgnoreFiles.filter((x) => fs.existsSync(x))[0];

const scanpath = prg.path ?? prg.jspath ?? '.';

const log = reporting.open({
  colors: !!prg.colors,
  colorwarn,
  jsRepo: jsrepolocation,
  insecure: prg.insecure,
  outputformat: prg.outputformat,
  outputpath: prg.outputpath,
  path: scanpath,
  verbose: !!prg.verbose,
});

const severity = prg.severity ?? 'none';

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
  insecure: !!prg.insecure,
  deep: !!prg.deep,
  ext: prg.ext ?? 'js',
};

function exitWithError(error: unknown) {
  log.error(colorwarn(String(error)));
  process.exitCode = 1;
  log.close();
}

function scan() {
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

  Promise.all(
    jsrepolocation.map((jsr) =>
      jsr.match(/^https?:\/\//) ? repo.loadrepository(jsr, config) : repo.loadrepositoryFromFile(jsr, config),
    ),
  )
    .then(async (jsRepos) => {
      const scans: Promise<void>[] = [];
      let scanError: unknown;
      const failed = (error: unknown) => {
        scanError = error;
      };
      await new Promise<void>((done) => {
        resolve
          .scanJsFiles(config.path, config)
          .on('jsfile', (file) => {
            jsRepos.forEach((jsRepo) => {
              scans.push(scanner.scanJsFile(file, jsRepo, config).catch(failed));
            });
          })
          .on('bowerfile', (bowerfile) => {
            jsRepos.forEach((jsRepo) => {
              const bowerRepo = repo.asbowerrepo(jsRepo);
              scans.push(scanner.scanBowerFile(bowerfile, bowerRepo, config).catch(failed));
            });
          })
          .on('fail', (file, err) => failed(`Could not scan ${file}: ${err ?? 'Unknown error'}`))
          .on('error', failed)
          .on('end', done);
      });
      await Promise.all(scans);
      if (scanError !== undefined) throw scanError;
      process.exitCode = failProcess ? config.exitwith : 0;
      log.close();
    })
    .catch(exitWithError);
}

try {
  if (!severityParser.safeParse(severity).success) {
    throw new Error(
      `Invalid severity level (${severity}). Valid levels are: ${Object.keys(severityLevels).join(', ')}`,
    );
  }

  log.info(`retire.js v${retire.version}`);

  if (prg.cacert) {
    if (!fs.existsSync(prg.cacert)) {
      throw new Error(`Could not read cacert file: ${prg.cacert}`);
    }
    config.cacertbuf = fs.readFileSync(prg.cacert);
  }

  if (ignorefile) {
    config.ignore.pathsAsString = parseIgnoreFile(ignorefile, config);
  }
  config.ignore.paths = config.ignore.pathsAsString
    .map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .map((p) => p.replace(/[*]{1,2}/g, (a) => (a.length == 2 ? '.*' : '[^/]*')))
    .map((s) => new RegExp(s));

  scan();
} catch (error) {
  exitWithError(error);
}