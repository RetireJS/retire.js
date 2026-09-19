# Contributing

Thanks for considering a contribution to Retire.js.

## Pull requests

- Keep PRs focused on a single change (one bug fix, one library addition, one feature). Unrelated changes make review harder and should go in separate PRs.
- All commits must be signed.
- Describe *why* the change is needed, not just what changed.

## Node CLI (`node/`)

See [node/README.md](node/README.md) for usage and options.

- Build and run the test suite before submitting: `npm run build && npm run test` (specs import from `lib/`, not `src/`, so the build step is required).
- Run `npm run check` (lint + typecheck).
- Tests should be split into one test file per module being tested — e.g. don't bundle tests for `x.ts` and `y.ts` into a shared spec file unless there's no reasonable way to separate them.

## Vulnerability repository (`repository/`)

See [repository/README.md](repository/README.md) for the entry format.

- Make changes in `jsrepository-master.json` only. Never edit `jsrepository.json` directly (it's generated) or submit to `npmrepository.json` (deprecated).
- After editing `jsrepository-master.json`, regenerate derived files with `node convertToVersioned`.
- Before submitting, run `node validate` and `node test-detection.js`.
- Each vulnerability entry needs a `severity`, `cwe`, and at least one identifier (`CVE`, `githubID`, `pr`, or `issue`).

## Browser extensions (`chrome/`, `firefox/`)

See [chrome/README.md](chrome/README.md) and [firefox/README.md](firefox/README.md) for extension-specific details. Note the Firefox extension is deprecated.
