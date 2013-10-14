Retire.js
=========
#### What you require you must also retire

There is a pletora of javascript libraries for use on the web and in node.js apps out there. This greatly simplifies,
but we need to stay update on security fixes. "Using Components with Known Vulnerabilities" is now a part of the 
[OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) and insecure
can libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect use of version with 
known vulnerabilities.

Retire.js has two parts:

1. A command line scanner
2. A Chrome plugin

Command line scanner
--------------------
_Description_


Chrome plugin
-------------
_Description_

Windows quirks
---------------
Requires NTFS filesystem, manually create the symlink with the following commands as administrator:
```
cd node\lib\
del retire.js
node --eval "require('fs').symlinkSync('../../chrome/js/retire.js', 'retire.j
s', 'file')"

