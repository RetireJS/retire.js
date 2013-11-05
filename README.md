Retire.js
=========
#### What you require you must also retire

There is a pletora of JavaScript libraries for use on the web and in node.js apps out there. This greatly simplifies development,
but we need to stay up-to-date on security fixes. "Using Components with Known Vulnerabilities" is now a part of the 
[OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) and insecure libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect the use of JS-library versions with 
known vulnerabilities.

Retire.js has three parts:

1. [A command line scanner](https://github.com/bekk/retire.js/tree/master/node)
2. [A Chrome extension](https://github.com/bekk/retire.js/tree/master/chrome)
3. [A grunt plugin](https://github.com/bekk/grunt-retire)

Command line scanner
--------------------
Scan a web app or node app for use of vulnerable JavaScript libraries and/or node modules.


Chrome extension
-------------
Scans visited sites for references to insecure libraries, and puts warnings in the developer console. A icon on the address bar displays will also indicated if vulnerable libraries were loaded.


Grunt plugin
------------
A Grunt task for running Retire.js as part of your application's build routine, or some other automated workflow.