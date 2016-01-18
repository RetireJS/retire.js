Command line scanner looking for use of known vulnerable js files and node modules in web projects and/or node projects.

Install
-------

    npm install -g retire


Usage
-----

````
Usage: retire [options]

Options:

-h, --help              output usage information
-V, --version           output the version number

-p, --package           limit node scan to packages where parent is mentioned in package.json (ignore node_modules)
-n, --node              Run node dependency scan only
-j, --js                Run scan of JavaScript files only
-v, --verbose           Show identified files (by default only vulnerable files are shown)
-x, --dropexternal      Don't include project provided vulnerability repository
-c, --nocache           Don't use local cache

--jspath <path>         Folder to scan for javascript files
--nodepath <path>       Folder to scan for node files
--path <path>           Folder to scan for both
--jsrepo <path|url>     Local or internal version of repo
--noderepo <path|url>   Local or internal version of repo
--proxy <url>           Proxy url (http://some.sever:8080)
--outputformat <format> Valid formats: text, json
--outputpath <path>     File to which output should be written
--ignore <paths>        Comma delimited list of paths to ignore
--ignorefile <path>     Custom .retireignore file, defaults to .retireignore
--exitwith <code>       Custom exit code (default: 13) when vulnerabilities are found
````


Source code / Reporting an issue
--------------------------------
The source code and issue tracker can be found at [https://github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js)
