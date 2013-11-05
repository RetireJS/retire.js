There is a plethora of JavaScript libraries for use on the web and in node.js apps out there. They greatly simplify the development process, but also require us to stay updated on new library versions and security fixes. "Using Components with Known Vulnerabilities" is now a part of the 
[OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) and insecure libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect use of libraries with 
known vulnerabilities.

Retire.js has three parts:

1. [A command line scanner](https://github.com/bekk/retire.js/tree/master/node)
2. [A Chrome extension](https://github.com/bekk/retire.js/tree/master/chrome)
3. [A grunt plugin](https://github.com/bekk/grunt-retire)

Command line scanner
--------------------
Scan a web app or node app for use of vulnerable JavaScript libraries and/or node modules.
```
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
```

Chrome extension
-------------
Scans visited sites for references to insecure libraries, and puts warnings in the developer console. An icon on the address bar displays will also indicated if vulnerable libraries were loaded. This extension is not meant to be enabled all the time, but rather something you enable when you want to assess your site.

Grunt plugin
-------------
Scans the given grunt enabled project for JavaScript files with known vulnerabilites, and breaks if it finds any. See examples on the [repo page](https://github.com/bekk/grunt-retire).

The source
----------------
The source of vulnerabilities is a manually maintained [JSON file](https://github.com/bekk/retire.js/tree/master/repository) in the GitHub repository. It was created by looking through release notes and issue trackers for the most common frameworks. If you see a framework or vulnerability missing, feel free to create a pull request (or register as an issue).

Detection
---------------
To detect a given version of a given component, Retire.js uses filename or URL. If that fails, it will download/open the file and look for specific comments within the file. If that also fails, there is the possibility to use hashes for minified files. And if that fails as well, the Chrome plugin will run code in a sandbox to try to detect the component and version. This last detection mechanisms is not available in the command line scanner, as running arbitrary JavaScript-files in the node-process could have unwanted consequences. If anybody knows of a good way to sandbox the code on node, feel free to register an issue or contribute.

It's important to note that even though your site is using a vulnerable library, that does not necessarily mean your site is vulnerable. It depends on whether and how your site exercises the vulnerable code. That said, it's better to be safe than sorry.


Want to help out?
---------------------
We need help in both improving the scanner and plugin, and keeping the repository of known vulnerabilities up to date. You can contribute at [https://github.com/bekk/retire.js](https://github.com/bekk/retire.js)
