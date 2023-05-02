declare module 'read-installed' {
  export type PkgInfo = {
    dependencies: Dependency[];
  };
  export type Dependency = {
    _requiredBy: string;
  };

  export default function readInstalled(
    path: string,
    options: Record<string, string>,
    cb: (er: Error, pkginfo: PkgInfo) => void,
  ): void;
}
