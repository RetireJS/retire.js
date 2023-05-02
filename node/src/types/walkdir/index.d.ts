declare module 'walkdir' {
  import { EventEmitter } from 'stream';
  export function find(path: string, options: Record<string, boolean>): EventEmitter;
}
