Command line scanner looking for use of known vulnerable js files and node modules in web projects and/or node projects.

Install
-------

    npm install retire
    

Usage
-----

````
Usage: retire [options]

Options:

-h, --help       output usage information

-v, --verbose    output all identified JavaScript libraries (not just vulnerable ones)
-p, --package    limit node scan to packages where parent is mentioned in package.json (ignore node_modules folder)
-n, --node       Run node dependency scan only
-j, --js         Run scan of JavaScript files only (ignore node)

--jspath <path>  Folder to scan for javascript files (node-scan always scans current folder and subfolders)
````


Source code / Reporting an issue
--------------------------------
The source code and issue tracker can be found at [https://github.com/bekk/retire.js](https://github.com/bekk/retire.js)
