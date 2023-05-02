type LogMethod = (...message: unknown[]) => void;

export function info(options: { logger?: LogMethod }) {
  return function (...message: unknown[]) {
    (options.logger || console.log)(message);
  };
}

export function warn(options: { warnlogger?: LogMethod; logger?: LogMethod }) {
  return function (...message: unknown[]) {
    (options.warnlogger || options.logger || console.warn)(message);
  };
}

export function pick(p: Record<string, unknown>, keys: string[]): Record<(typeof keys)[number], unknown> {
  const result: Record<(typeof keys)[number], unknown> = {};
  keys.forEach((k) => {
    if (k in p) {
      result[k] = p[k];
    }
  });
  return result;
}

export function flatten<T>(e: T[][]): T[] {
  return e.reduce((x, y) => x.concat(y), [] as T[]);
}
