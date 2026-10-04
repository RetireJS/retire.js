import { Options } from '../lib/types';

export const options: Options = {
  path: '.',
  nocache: true,
  cachedir: '',
  ignore: { paths: [], pathsAsString: [] },
  severity: 'none',
  exitwith: 13,
  colorwarn: (message) => message,
  log: {
    info() {},
    debug() {},
    warn() {},
    error() {},
    logDependency() {},
    logVulnerableDependency() {},
    close() {},
  },
};
