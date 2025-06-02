# Changelog

## [5.2.7]

### Performance fix

- Upgrade to ASTronomical 2.0.0 to reduce memory usage

## [5.2.6]

### Bugfix

- Don't crash on invalid code when using deep scan

## [5.2.5]

### Bugfix

- CLI argument `--ext` was not working

## [5.2.4]

### Bugfix

- Fix name vs group for scoped components in CycloneDX output

## [5.2.3]

### Bugfix

- Fix license handling for complex licenses

## [5.2.2]

### Bugfix

- Encode purls correctly in SBOM

## [5.2.1]

### Bugfix

- Add missing CWEs in response

## [5.2.0]

### Enhancement

- Add license information to SBOM

## [5.1.4]

### Bugfix

- Fix bug where deepScan would sometimes not report vulnerabilities

## [5.1.3]

### Bugfix

- Use URI detector on file paths as well

## [5.1.2]

### Bugfix

- JSON format should not include results without vulnerabilities unless `--verbose` is specified.

## [5.1.1]

### Bugfix

- Remove duplicates in filename output in CycloneDX JSON formats

## [5.1.0]

### Add

- Support for CycloneDX 1.6 JSON as output format
- Adding file location as property in CycloneDX 1.4 JSON output

## [5.0.1]

### Fix

- Fix filename issue for windows file paths

## [5.0.0]

No changes. Just moving from beta to final.

## [5.0.0-beta.1]

### Added

- Deepscan option with `--deep` where retire.js will also try to detect libraries using JavaScript AST (slower)

## [4.4.2]

### Fix

- Fix matching to include all matches

## [4.4.1]

### Chore

- Dependency upgrades

## [4.4.0]

### Added

- Adding proper repository validation to ensure it's on the expected format

## [4.3.4]

### Bugfix

- Bug: `--jspath` is not being honoured

## [4.3.3]

### Bugfix

- Fixes #420 where ignore was not honoured

## [4.3.2]

### Bugfix

- Types did not work for `lib/retire.js` due to symlinked type file

## [4.3.1]

### Bugfix

- Should always include detected libraries in SBOM reports regardless of if they are vulnerable or not

## [4.3.0]

### Changes

- Support basePurl in repository to generate purls in SBOM

## [4.2.3]

### Bugfix

- Generate correct purl for moment.js

## [4.2.2]

### Bugfix

- Proxy setting did not work

## [4.2.1]

### Changes

- Fix provenance settings

## [4.2.0]

### Changes

- Use prettier to get formatting of code
- Add provenance

## Security fixes

- Upgrade dependencies

## [4.1.1]

### Bugfixes

- Handle error if OSV does not have library or version

## [4.1.0]

### Additions

- Option to check results for the component from OSV
- Option to use more than one JS repository

### Bugfixes

- Remove dropexternal as it never worked

## [4.0.1]

### Breaking changes

- Not really a breaking change as the change was introduced in 4.0.0, but node.js >= 14.0.0 is required to run retire.js >= 4.0.0 going forward

## [4.0.0]

### Breaking changes

- npm scanning no longer supported

### Changes

- Complete rewrite to typescript

## [3.2.3]

- Fix caching bug in CycloneDX JSON output

## [3.2.2]

- Fix bug in CycloneDX JSON output (wrapped components array)

## [3.2.1]

- Remove unintended use of arrow functions

## [3.2.0]

- Add `--ext` to allow specifying other file extensions

## [3.1.3]

- Fixes a typo

## [3.1.2]

- Remove some unused variables and tmp files

## [3.1.1]

- Update VM2 due to vuln in that library

## [3.1.0]

- Adding support for cycloneDX JSON format
- Updating CycloneDX XML format to version 1.4
- Adding schema parsing tests for cyclonedx

## [3.0.7]

### Fixes

- Updating proxy library to fix proxy issues

## [3.0.6]

### Security

- Switch the `colors` package with `ansi-colors`

## [3.0.4] / [3.0.5]

### Security

- Pin colors dependency to avoid DOS from colors author

## [3.0.3]

### Bug

- Fix version number

## [3.0.2]

### Dependency update

- always output JSON to stdout, to avoid conflict with deprecation warning

## [3.0.1]

### Dependency update

- glob-parent, lodash and hosted-git-info had vulnerabilities and was updated

## [3.0.0]

### Deprecation notice

- The node scanner is deprecated: https://github.com/RetireJS/retire.js/wiki/Deprecating-the-node.js-scanner

## [2.2.5]

### Dependency update

- y18n had a vulnerability and was updated

## [2.2.4]

### Bugfix

- Fixes [#343](https://github.com/RetireJS/retire.js/pull/343) where symlink to nonexistent file causes it to crash with exception. Now it will log it as warn instead.

## [2.2.3]

### Bugfix

- Fixes [#337](https://github.com/RetireJS/retire.js/issues/337) where symlinks are not read

## [2.2.2]

### Bugfix

- Fixes [#334](https://github.com/RetireJS/retire.js/issues/334) where detected libraries without vulnerabilities show in output even when verbose is not specified

## [2.2.1]

### Bugfix

- Fixes [#321](https://github.com/RetireJS/retire.js/issues/321) where write output to file did not always work as expected

## [2.2.0]

### Added

- Support `--cacert <path>` or `--insecure` when loading the repos (thanks to [adamcohen](https://github.com/adamcohen)) [PR#322](https://github.com/RetireJS/retire.js/pull/322)

## [2.1.1] - 2020-03-20

### Bugfix

- Fix compatibility with node 6

## [2.1.1] - 2020-03-16

### Modified

- Remove `request` as it is deprecated

## [2.1.0] - 2020-03-16

### Modified

- Support ** and \* in ignore paths (** = any number of folders)
