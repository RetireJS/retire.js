Retire.js
=========

[![Retire Status](http://retire.insecurity.today/api/image?uri=https://raw.githubusercontent.com/RetireJS/retire.js/master/node/package.json)](http://retire.insecurity.today/api/image?uri=https://raw.githubusercontent.com/RetireJS/retire.js/master/node/package.json)

#### What you require you must also retire

There is a plethora of JavaScript libraries for use on the Web and in Node.JS apps out there. This greatly simplifies development,but we need to stay up-to-date on security fixes. "Using Components with Known Vulnerabilities" is now a part of the [OWASP Top 10](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities) list of security risks and insecure libraries can pose a huge risk to your Web app. The goal of Retire.js is to help you detect the use of JS-library versions with known vulnerabilities.

Retire.js can be used in many ways:

1. [As  command line scanner](https://github.com/RetireJS/retire.js/tree/master/node)
2. [As a grunt plugin](https://github.com/bekk/grunt-retire)
2. [As a gulp task](#user-content-gulp-task)
3. [As a Chrome extension](https://github.com/RetireJS/retire.js/tree/master/chrome)
4. [As a Firefox extension](https://github.com/RetireJS/retire.js/tree/master/firefox)
5. [As a Burp and OWASP Zap plugin](https://github.com/h3xstream/burp-retire-js)

Command line scanner
--------------------
Scan a web app or node app for use of vulnerable JavaScript libraries and/or Node.JS modules. In the source code folder of the application folder run:
```
$ npm install -g retire
$ retire
```

Grunt plugin
------------
A [Grunt task for running Retire.js](https://github.com/bekk/grunt-retire) as part of your application's build routine, or some other automated workflow.

Gulp task
---------
An example of a Gulp task which can be used in your gulpfile to watch and scan your project files automatically. You can modify the watch patterns and (optional) Retire.js options as you like.

```javascript
var gulp = require('gulp');
var spawn = require('child_process').spawn;
var gutil = require('gulp-util');

gulp.task('retire:watch', ['retire'], function (done) {
    // Watch all javascript files and package.json
    gulp.watch(['js/**/*.js', 'package.json'], ['retire']);
});

gulp.task('retire', function() {
    // Spawn Retire.js as a child process
    // You can optionally add option parameters to the second argument (array)
    var child = spawn('retire', [], {cwd: process.cwd()});
    
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', function (data) {
        gutil.log(data);
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', function (data) {
        gutil.log(gutil.colors.red(data));
        gutil.beep();
    });
});

```

Chrome and firefox extensions 
-------------
Scans visited sites for references to insecure libraries, and puts warnings in the developer console. An icon on the address bar displays will also indicate if vulnerable libraries were loaded.


Burp and OWASP ZAP plugin
-------------------------
[@h3xstream](https://github.com/h3xstream) has adapted Retire.js as a [plugin](https://github.com/h3xstream/burp-retire-js) for the penetration testing tools [Burp](http://portswigger.net/burp/) and [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project). An alternative OWASP ZAP plugin exists at https://github.com/nikmmy/retire/

Donate
------
<a href="https://www.paypal.me/eoftedal"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif"></a>
<a href="https://flattr.com/submit/auto?fid=g3q3vw&url=https%3A%2F%2Fgithub.com%2FRetireJS%2Fretire.js%2F" target="_blank"><img src="https://button.flattr.com/flattr-badge-large.png" alt="Flattr this" title="Flattr this" border="0"></a>

Donations will be used to fund the maintainance of the tool and vulnerability repo.

