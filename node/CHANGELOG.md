# Changelog

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
- Support ** and * in ignore paths (** = any number of folders)

