Command line scanner looking for use of known vulnerable js files and node modules in web projects and/or node projects.

Install
-------

    npm install retire
    

Usage
-----

````
Usage: retire [options]

Options:

-h, --help         output usage information
-V, --version      output the version number

-p, --package      limit node scan to packages where parent is mentioned in package.json (ignore node_modules)
-n, --node         Run node dependency scan only
-j, --js           Run scan of JavaScript files only
-v, --verbose      Show identified files (by default only vulnerable files are shown)

--jspath <path>    Folder to scan for javascript files
--nodepath <path>  Folder to scan for node files
--path <path>      Folder to scan for both
--jsrepo <path>    Local version of repo
--noderepo <path>  Local version of repo
````


Source code / Reporting an issue
--------------------------------
The source code and issue tracker can be found at [https://github.com/bekk/retire.js](https://github.com/bekk/retire.js)
