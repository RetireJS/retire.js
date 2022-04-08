# Changelog

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
