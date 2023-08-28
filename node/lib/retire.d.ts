import { Repository, Component, Hasher } from './types';

export declare function check(component: string, version: string, repo: Repository): Component[];

export declare function replaceVersion(jsRepoJsonAsText: string): string;

export declare function isVulnerable(results: Component[]): boolean;

export declare function scanUri(uri: string, repo: Repository): Component[];

export declare function scanFileName(fileName: string, repo: Repository): Component[];

export declare function scanFileContent(content: string, repo: Repository, hasher: Hasher): Component[];

export declare const version: string;
