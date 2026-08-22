# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository structure

This is a monorepo with two main parts:

- **`node/`** — The CLI tool and core library (TypeScript, published to npm as `retire`). Source in `node/src/`, compiled output in `node/lib/`.
- **`repository/`** — The vulnerability database and tooling to manage it.

## Node CLI (node/)

```bash
cd node
npm install
npm run build       # compile TypeScript → lib/
npm run test        # run the test suite (node/spec/tests/*.spec.ts)
npm run check       # lint + typecheck
npm run lint        # eslint --fix
npm run typecheck   # tsc --noEmit
```

### Testing

Tests use the built-in [`node:test`](https://nodejs.org/api/test.html) runner (`describe`/`it` with
`node:assert`), not jest.

**The specs import from `../../lib/`, not `../../src/`, so `npm run build` must be run before
`npm run test`** — otherwise you are testing the previously compiled output and your changes will
appear to have no effect:

```bash
cd node
npm run build && npm run test
```

Run a single test file:
```bash
cd node
TS_NODE_PROJECT=tsconfig.spec.json node --require ts-node/register --test spec/tests/contentscan.spec.ts
```

Run a single test by name (matched as a regex against the `it(...)` description):
```bash
cd node
TS_NODE_PROJECT=tsconfig.spec.json node --require ts-node/register --test \
  --test-name-pattern 'should validate report according to schema' spec/tests/cyclonedx.spec.ts
```

Reporters that emit CycloneDX are validated against the JSON schemas bundled in
`node/spec/schema/`. When adding support for a new spec version, add its `bom-<version>.schema.json`
there too.

## Vulnerability repository (repository/)

The source of truth is `jsrepository-master.json`. The other `jsrepository*.json` files are derived outputs and must be kept in sync.

After editing `jsrepository-master.json`, regenerate all derived files:
```bash
cd repository
node convertToVersioned
```

Validate that all derived files are in sync and the format is correct:
```bash
cd repository
node validate
```

Test that detection regexes actually match the real library files (downloads from CDN, cached in `repository/tmp/`):
```bash
cd repository
node test-detection.js
node test-detection.js <library-name>   # test a single library
```

**Before submitting a PR:** always run `validate` and `test-detection.js`.

## Repository format

Entries in `jsrepository-master.json` use `§§version§§` as a placeholder for a version-capturing regex group. Required fields per vulnerability:

- `severity` — align with CVE/GHSA severity when available
- `cwe` — array of CWE IDs
- `identifiers` — at least one of: `CVE`, `githubID`, `pr`, `issue`

Version ranges: omit `atOrAbove` if no lower bound is known; use `"999.0.0"` for `below` when no upper bound is known.

Do **not** edit `jsrepository.json` directly — it is generated from master. Do **not** submit to `npmrepository.json` (deprecated).

## Core detection logic (node/src/)

- `retire.ts` — core scanning functions: `scanUri`, `scanFileName`, `scanFileContent`, `check`
- `scanner.ts` — filesystem walker, orchestrates scanning files and npm packages
- `deepscan.ts` — AST-based detection for libraries that embed version strings in non-obvious ways
- `repo.ts` — loads and validates the repository (uses zod schema)
- `cli.ts` — commander-based CLI entry point
- `reporters/` — output formatters (console, JSON, CycloneDX SBOM)

## Bumping the version number

When bumping the version number of node/package.json, also update the version number in:
- node/lib/retire.js
- chrome/extension/manifest.json
- chrome/extension-no-func/manifest.json
