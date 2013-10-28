Retire.js
=========
#### What you require you must also retire

There is a pletora of JavaScript libraries for use on the web and in node.js apps out there. This greatly simplifies,
but we need to stay update on security fixes. "Using Components with Known Vulnerabilities" is now a part of the 
[OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) and insecure
can libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect the use of JS-library versions with 
known vulnerabilities.

Retire.js has two parts:

1. A command line scanner
2. A Chrome plugin

Command line scanner
--------------------
Scan a web app or node app for use of vulnerable JavaScript libraries and/or node modules.


Chrome plugin
-------------
Scans visisted sites for references to insecure libraries, and puts warnings in the developer console. A icon on the address bar displays will also indicated if vulnerable libraries were loaded.

Windows quirks
---------------
Requires NTFS filesystem, manually create the symlink with the following commands as administrator:
```
cd node\lib\
del retire.js
node --eval "require('fs').symlinkSync('../../chrome/js/retire.js', 'retire.js', 'file')"

