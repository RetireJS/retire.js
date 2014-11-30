Retire.js
=========
#### What you require you must also retire

There are a plethora of JavaScript libraries for use on the Web and in Node.JS apps out there. This greatly simplifies development,
but we need to stay up-to-date on security fixes. "Using Components with Known Vulnerabilities" is now a part of the 
[OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) and insecure libraries can pose a huge risk for your Web app. The goal of Retire.js is to help you detect the use of JS-library versions with 
known vulnerabilities.

Retire.js has four parts:

1. [A command line scanner](https://github.com/bekk/retire.js/tree/master/node)
2. [A Chrome extension](https://github.com/bekk/retire.js/tree/master/chrome)
3. [A grunt plugin](https://github.com/bekk/grunt-retire)
4. [Burp and OWASP Zap plugin](https://github.com/h3xstream/burp-retire-js)

Command line scanner
--------------------
Scan a web app or node app for use of vulnerable JavaScript libraries and/or Node.JS modules.


Chrome extension
-------------
Scans visited sites for references to insecure libraries, and puts warnings in the developer console. An icon on the address bar will also indicate if vulnerable libraries were loaded.


Grunt plugin
------------
A [Grunt task for running Retire.js](https://github.com/bekk/grunt-retire) as part of your application's build routine, or some other automated workflow.

Burp and OWASP ZAP plugin
-------------------------
[@h3xstream](https://github.com/h3xstream) has adapted Retire.js as a plugin for both of the penetration testing tools [Burp](http://portswigger.net/burp/) and [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project).
