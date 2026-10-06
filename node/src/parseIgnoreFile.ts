import { Options } from "./types";
import fs from "fs";
import path from "path";
import { ignoreFileParser } from "./types";

export function parseIgnoreFile(ignorefile: string, config: Options): string[] {
  if (!fs.existsSync(ignorefile)) {
    throw new Error(`Could not read ignore file: ${ignorefile}`);
  }
  if (ignorefile.endsWith('.json')) {
    try {
      config.ignore.descriptors = ignoreFileParser.parse(JSON.parse(fs.readFileSync(ignorefile, 'utf-8')));
    } catch (e) {
      throw new Error(`Invalid ignore file: ${ignorefile}`);
    }
    const ignoredPaths =
    config.ignore.descriptors
    ?.map((x) => ('path' in x ? x.path : undefined))
    ?.filter((x): x is string => x != undefined) ?? [];
    return config.ignore.pathsAsString.concat(ignoredPaths);
  } else {
    const lines = fs
    .readFileSync(ignorefile, 'utf-8')
    .split(/\r\n|\n/g)
    .filter((e) => e !== '');
    const ignored = lines.map((e) => {
      return e[0] === '@' ? e.slice(1) : path.resolve(e);
    });
    return config.ignore.pathsAsString.concat(ignored);
  }
}
