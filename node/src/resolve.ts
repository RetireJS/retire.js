import { EventEmitter as Emitter } from 'events';
import * as fs from 'fs';
import * as walkdir from 'walkdir';
import { Options } from './types';

export function scanJsFiles(path: string, options: Options): Emitter {
  const finder = walkdir.find(path, { follow_symlinks: false, no_return: true });
  const ext = (options.ext || 'js').split(',').map((e) => `.${e}`);
  function onFile(file: string) {
    if (ext.some((e) => file.endsWith(e))) {
      finder.emit('jsfile', file);
    }
    if (file.match(/\/bower.json$/)) {
      finder.emit('bowerfile', file);
    }
  }
  finder.on('file', onFile);
  finder.on('link', (link) => {
    if (fs.existsSync(link)) {
      const file = fs.realpathSync(link);
      if (fs.lstatSync(file).isFile()) {
        onFile(link);
      }
    } else {
      options.log.warn(`Could not follow symlink: ${link}`);
    }
  });
  return finder;
}
