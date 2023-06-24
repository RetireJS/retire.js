Command line scanner looking for use of known vulnerable js files and node modules in web projects and/or node projects.

Install
-------

    npm install -g retire


Usage
-----

````
Usage: retire [options]

Options:
  -V, --version            output the version number
  -v, --verbose            Show identified files (by default only vulnerable files are shown)
  -c, --nocache            Don't use local cache
  --jspath <path>          Folder to scan for javascript files
  --path <path>            Folder to scan for both
  --jsrepo <path|url>      Local or internal version of repo. Can be multiple comma separated. Default: 'central')
  --cachedir <path>        Path to use for local cache instead of /tmp/.retire-cache
  --proxy <url>            Proxy url (http://some.host:8080)
  --outputformat <format>  Valid formats: text, json, jsonsimple, depcheck (experimental), cyclonedx and cyclonedxJSON
  --outputpath <path>      File to which output should be written
  --ignore <paths>         Comma delimited list of paths to ignore
  --ignorefile <path>      Custom ignore file, defaults to .retireignore / .retireignore.json
  --severity <level>       Specify the bug severity level from which the process fails. Allowed levels none, low, medium, high, critical.
                           Default: none
  --exitwith <code>        Custom exit code (default: 13) when vulnerabilities are found
  --colors                 Enable color output (console output only)
  --insecure               Enable fetching remote jsrepo/noderepo files from hosts using an insecure or self-signed SSL (TLS) certificate
  --ext <extensions>       Comma separated list of file extensions for JavaScript files. The default is "js"
  --cacert <path>          Use the specified certificate file to verify the peer used for fetching remote jsrepo/noderepo files
  --includeOsv             Include OSV advisories in the output
  -h, --help               display help for command
````

The `depcheck` output format mimics the output of OWASP Dependency Check, but lacks some information compared to OWASP Dependency Check, because that information is not in the repo.
The `cyclonedx` output format is based on based on the https://github.com/CycloneDX spec.

.retireignore
-------------
````
@qs                                                             # ignore this module regardless of location
node_modules/connect/node_modules/body-parser/node_modules/qs   # ignore specific path
````
Due to a bug in ignore resolving, please upgrade to >= 1.1.3

.retireignore.json
------------------
````
[
	{
		"component": "jquery",
		"identifiers" : { "issue": "2432"},
		"justification" : "We dont call external resources with jQuery"
	},
	{
		"component": "jquery",
		"version" : "2.1.4",
		"justification" : "We dont call external resources with jQuery"
	},
	{
		"path" : "node_modules",
		"justification" : "The node modules are only used for building - client side dependencies are using bower"
	}

]
````

Source code / Reporting an issue
--------------------------------
The source code and issue tracker can be found at [https://github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js)
