#!/usr/bin/env node

import * as utils from "./utils";
import { program } from "commander";

import * as retire    from './retire';
import * as repo      from './repo';
import * as resolve   from './resolve';
import * as scanner   from './scanner';
import * as reporting from './reporting';
import { forwardEvent as forward } from './utils';
import os        from 'os';
import path      from 'path';
import fs        from 'fs';
import colors    from 'ansi-colors';
import { EventEmitter } from "events";
import { Finding, Options, Repository, severityLevels } from "./types";
import * as z from "zod";

const events = new EventEmitter();
let failProcess = false;
const defaultIgnoreFiles = ['.retireignore', '.retireignore.json'];

/*
 * Parse command line flags.
 */
const prg = program
  .version(retire.version)
  .option('-v, --verbose', 'Show identified files (by default only vulnerable files are shown)')
  .option('-x, --dropexternal', "Don't include project provided vulnerability repository")
  .option('-c, --nocache', "Don't use local cache")
  .option('--jspath <path>', 'Folder to scan for javascript files')
  .option('--path <path>', 'Folder to scan for both')
  .option('--jsrepo <path|url>', 'Local or internal version of repo')
  .option('--cachedir <path>', 'Path to use for local cache instead of /tmp/.retire-cache')
  .option('--proxy <url>', 'Proxy url (http://some.host:8080)')
  .option('--outputformat <format>', 'Valid formats: text, json, jsonsimple, depcheck (experimental), cyclonedx and cyclonedxJSON')
  .option('--outputpath <path>', 'File to which output should be written')
  .option('--ignore <paths>', 'Comma delimited list of paths to ignore')
  .option('--ignorefile <path>', 'Custom ignore file, defaults to .retireignore / .retireignore.json')
  .option('--severity <level>', 'Specify the bug severity level from which the process fails. Allowed levels none, low, medium, high, critical. Default: none')
  .option('--exitwith <code>', 'Custom exit code (default: 13) when vulnerabilities are found')
  .option('--colors', 'Enable color output (console output only)')
  .option('--insecure', 'Enable fetching remote jsrepo/noderepo files from hosts using an insecure or self-signed SSL (TLS) certificate')
  .option('--ext <extensions>', 'Comman separated list of file extensions for javascript files. The default is "js"')
  .option('--cacert <path>', 'Use the specified certificate file to verify the peer used for fetching remote jsrepo/noderepo files')
  .parse()
  .opts();

const colorwarn = prg.colors ? colors.red : (x:string) => x;
const jsrepolocation = prg.jsrepo ?? "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";

const ignorefile = prg.ignoreFile ?? defaultIgnoreFiles.filter(function(x){ return fs.existsSync(x); })[0];

const scanpath = prg.path ?? ".";

const log = reporting.open({
  colors: !!prg.colors,
  colorwarn,
  jsRepo: jsrepolocation,
  outputformat: prg.outputformat,
  outputpath: prg.outputpath,
  path: scanpath,
  verbose: !!prg.verbose
});

const severity = prg.severity ?? "none";
if (!(severity in severityLevels)) {
  exitWithError('Error: Invalid severity level (' + severity + '). Valid levels are: ' + Object.keys(severityLevels).join(', '));
}


const config: Options = {
  path: scanpath,
  ignore: {
    paths: prg.ignore?.split(",")?.map((x: string) => path.resolve(x)) ?? [],
    pathsAsString: [],
    descriptors: []
  },
  colorwarn,
  nocache: prg.nocache ? true : false,
  cachedir: prg.cachedir ?? path.resolve(os.tmpdir(), '.retire-cache/'),
  log: log,
  severity: severity,
  exitwith: prg.exitwith ?? 13
};

log.info("retire.js v" + retire.version);

function exitWithError(msg: string) {
  log.error(config.colorwarn(msg));
  process.exitCode = 1;
  log.close();
}

if(prg.cacert) {
  if (!fs.existsSync(prg.cacert)) {
    exitWithError('Error: Could not read cacert file: ' + prg.cacert);
  }
  config.cacertbuf = fs.readFileSync(prg.cacert);
}

const ignoreFileParser = z.array(z.object({
  justification: z.string()
}).and(z.object({
    path: z.string(),
  }).or(z.object({
    component: z.string(),
    version: z.string().optional(),
    identifiers: z.record(z.string(), z.string()).optional(),
  }))));

if(ignorefile) {
  if (!fs.existsSync(ignorefile)) {
    exitWithError('Error: Could not read ignore file: ' + ignorefile);
  }
  if (ignorefile.substr(-5) === ".json") {
    try {
      config.ignore.descriptors = ignoreFileParser.parse(JSON.parse(fs.readFileSync(ignorefile, "utf-8")));
    } catch(e) {
      exitWithError('Error: Invalid ignore file: ' + ignorefile);
    }
    const ignoredPaths = config.ignore.descriptors?.map((x) => "path" in x ? x.path : undefined)
      ?.filter((x): x is string => x != undefined) ?? [];
    config.ignore.pathsAsString = config.ignore.pathsAsString.concat(ignoredPaths);
  } else {
    const lines = fs.readFileSync(ignorefile, "utf-8").split(/\r\n|\n/g).filter((e) => e !== '');
    const ignored = lines.map(e => { return e[0] === '@' ? e.slice(1) : path.resolve(e); });
    config.ignore.pathsAsString = config.ignore.pathsAsString.concat(ignored);
  }
}
config.ignore.paths = config.ignore.pathsAsString
  .map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
  .map(p => p.replace(/[*]{1,2}/g, (a) => a.length == 2 ? ".*" : "[^/]*"))
  .map(s => new RegExp(s)
);

scanner.on('vulnerable-dependency-found', function(result: Finding) {
  const levels = result.results
    .map(function(r) {
      return r.vulnerabilities ? r.vulnerabilities.map(function(v) {
        return severityLevels[v.severity ?? 'critical'];
      }) : []; });
  const severity = utils.flatten(levels).reduce(function(x,y) { return x > y ? x : y; });
  if(severity >= severityLevels[config.severity]) {
    failProcess = true;
  }
});

scanner.on('vulnerable-dependency-found', log.logVulnerableDependency);
scanner.on('dependency-found', log.logDependency);


events.on('load-js-repo', function() {
  const loader = jsrepolocation.match(/^https?:\/\//) 
    ? repo.loadrepository(jsrepolocation, config)
    : repo.loadrepositoryFromFile(jsrepolocation, config);
  loader.on('stop', forward(events, 'stop'));
  loader.on('done', (repo) => {
    events.emit('scan-js', repo);
  });
});


events.on('scan-js', (jsRepo: Repository) => {
  resolve.scanJsFiles(config.path, config)
    .on('jsfile', function(file) {
      scanner.scanJsFile(file, jsRepo, config);
    })
    .on('bowerfile', function(bowerfile) {
      const bowerRepo = repo.asbowerrepo(jsRepo);
      scanner.scanBowerFile(bowerfile, bowerRepo, config);
    })
    .on('end', function() {
      events.emit('js-scanned');
    });
});

events.on('js-scanned', function() {
  events.emit('scan-done');
});

events.on('scan-done', function() {
  process.exitCode = failProcess ? config.exitwith : 0;
  log.close();
});


process.on('uncaughtException', function (err, ...rest) {
  console.warn('Exception caught: ', err, rest);
  console.warn(err.stack);
  process.exit(1);
});

events.on('stop', function(err) {
  exitWithError(err);
});

events.emit('load-js-repo');

