import * as fs from 'fs';
import * as crypto from 'crypto';

import consoleLogger from './reporters/console';
import jsonLogger from './reporters/json';
import depcheckLogger from './reporters/depcheck';
import cyclonedxLogger from './reporters/cyclonedx';
import cyclonedxJSONLogger from './reporters/cyclonedx-json';
import cyclonedxJSON1_6Logger from './reporters/cyclonedx-1_6-json';
import { Finding } from './types';

const loggers = {
  console: consoleLogger,
  text: consoleLogger,
  json: jsonLogger,
  depcheck: depcheckLogger,
  cyclonedx: cyclonedxLogger,
  cyclonedxJSON: cyclonedxJSONLogger,
  cyclonedxJSON1_6: cyclonedxJSON1_6Logger,
  clean: consoleLogger,
  jsonsimple: jsonLogger,
} as Record<string, ConfigurableLogger>;

export type LoggerOptions = {
  outputpath: string;
  verbose: boolean;
  colors: boolean;
  outputformat: string;
  jsRepo: string;
  path: string;
  colorwarn: (s: string) => string;
};

let colorwarn = (x: string) => {
  return x;
};

let verbose = false;

function hashContent(hash: string, content: Buffer | string) {
  const h = crypto.createHash(hash);
  h.update(content);
  return h.digest('hex');
}
export type Hasher = {
  md5: (file: Buffer | string) => string;
  sha1: (file: Buffer | string) => string;
  sha256: (file: Buffer | string) => string;
  sha512: (file: Buffer | string) => string;
};

export const hash: Hasher = {
  md5: (file: Buffer | string) => hashContent('md5', file),
  sha1: (file: Buffer | string) => hashContent('sha1', file),
  sha256: (file: Buffer | string) => hashContent('sha256', file),
  sha512: (file: Buffer | string) => hashContent('sha512', file),
};

export type Writer = {
  out: (...args: Parameters<(typeof console)['log']>) => void;
  err: (x: string) => void;
  close: (callback?: () => void) => void;
};

const writer: Writer = {
  out: console.log,
  err: (x: string) => {
    console.warn(colorwarn(x));
  },
  close: () => {
    return;
  },
};

export type Logger = {
  info: (x: string) => void;
  debug: (x: string) => void;
  warn: (x: string) => void;
  error: (x: string) => void;

  logDependency: (finding: Finding) => void;
  logVulnerableDependency: (finding: Finding) => void;
  close: (callback?: () => void) => void;
};

const logger: Logger = {
  info: (x: string) => {
    writer.out(x);
  },
  debug: (x: string) => {
    if (verbose) writer.out(x);
  },
  warn: (x: string) => {
    writer.err(x);
  },
  error: (x: string) => {
    writer.err(x);
  },

  logDependency: () => {
    return;
  },
  logVulnerableDependency: () => {
    return;
  },
  close: () => writer.close(),
};

export interface ConfigurableLogger {
  configure: (logger: Logger, writer: Writer, config: LoggerOptions, hash: Hasher) => void;
}

function configureFileWriter(config: LoggerOptions) {
  if (!config.outputpath) return;
  const fileDescriptor = fs.openSync(config.outputpath, 'w');
  if (fileDescriptor < 0) {
    console.error(`Could not open ${config.outputpath} for writing`);
    process.exit(9);
  }
  const fileOutput = {
    fileDescriptor,
    stream: fs.createWriteStream('', { fd: fileDescriptor, autoClose: false }),
  };
  const writeToFile = <T>(message: T) => {
    fileOutput.stream.write(message);
    fileOutput.stream.write('\n');
  };
  writer.out = writer.err = writeToFile;
  writer.close = () => {
    fileOutput.stream.on('finish', () => {
      fs.closeSync(fileOutput.fileDescriptor);
    });
    fileOutput.stream.end();
  };
}

export function open(config: LoggerOptions) {
  verbose = config.verbose ?? false;
  if (config.colors) colorwarn = config.colorwarn;
  const format = config.outputformat || 'console';
  if (!(format in loggers)) {
    console.warn(`Invalid outputformat: ${format}`);
    process.exit(1);
  }
  loggers[format].configure(logger, writer, config, hash);
  configureFileWriter(config);
  return logger;
}
