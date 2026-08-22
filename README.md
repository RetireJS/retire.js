# Retire.js

**What you require you must also retire**

There is a vast ecosystem of JavaScript libraries available for both web and Node.js applications. While these libraries significantly accelerate development, they also require ongoing maintenance to ensure security vulnerabilities are addressed promptly. In 2013, “Using Components with Known Vulnerabilities” was added to the OWASP Top 10￼ list of critical security risks, highlighting the serious threat that outdated or insecure dependencies can pose to web applications. Retire.js was created to help developers identify JavaScript library versions with known vulnerabilities, especially those that are not in package manifests, but simply downloaded and put in source control.

Retire.js can be used in many ways:

1. [As command line scanner](https://github.com/RetireJS/retire.js/tree/master/node)
2. [As a Chrome extension](https://github.com/RetireJS/retire.js/tree/master/chrome) - **Not** officially available in the Chrome web store
3. [As a Burp Extension](https://github.com/h3xstream/burp-retire-js) or [OWASP ZAP Add-on](https://www.zaproxy.org/docs/desktop/addons/retire.js/)
4. [As a Firefox extension](https://github.com/RetireJS/retire.js/tree/master/firefox) - **Deprecated** Let us know if you want to maintain and undeprecate it.
5. [A headless web site scanner](https://github.com/RetireJS/retire-site-scanner)
6. [As a grunt plugin (deprecated)](https://github.com/bekk/grunt-retire)
7. [As a gulp task (deprecated)](#user-content-gulp-task)

## Command line scanner

Scan a web app or node app for use of vulnerable JavaScript libraries and/or Node.JS modules. If you haven't already, you need to [install node/npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) first. In the source code folder of the application folder run:

```
$ npm install -g retire
$ retire
```

## SBOM generation

retire.js can generate SBOMs in the CycloneDX-format:

```
$ retire --outputformat cyclonedx
```

`cyclonedx` produces CycloneDX 1.4 XML. For JSON, and for newer spec versions, use `cyclonedxJSON` (1.4), `cyclonedxJSON1_6` or
`cyclonedxJSON1_7`. The `cyclonedxJSON1_6_VEX` and `cyclonedxJSON1_7_VEX` variants also include a `vulnerabilities` section.

By default retire.js will exit with code 13 if it finds vulnerabilities. This can be overridden with `--exitwith 0`.


## Chrome and firefox extensions

Scans visited sites for references to insecure libraries, and puts warnings in the developer console. An icon on the address bar displays will also indicate if vulnerable libraries were loaded.

## Burp Extension and OWASP ZAP Add-on

[@h3xstream](https://github.com/h3xstream) has adapted Retire.js as a [plugin](https://github.com/h3xstream/burp-retire-js) for the penetration testing tools [Burp](https://portswigger.net/burp/) and [OWASP ZAP](https://www.zaproxy.org).

The [OWASP ZAP](https://www.zaproxy.org) team officially supports a Retire.js add-on which is available via the ZAP Marketplace and is included by default in the ZAP weekly releases: https://www.zaproxy.org/docs/desktop/addons/retire.js/

## Headless site scanner

The retire-site-scanner https://github.com/RetireJS/retire-site-scanner can be used to scan a web site in headless mode (as opposed to using the chrome/firefox extensions)


## Grunt plugin (deprecated)

A [Grunt task for running Retire.js](https://github.com/bekk/grunt-retire) as part of your application's build routine, or some other automated workflow.

## Gulp task (deprecated)

An example of a Gulp task which can be used in your gulpfile to watch and scan your project files automatically. You can modify the watch patterns and (optional) Retire.js options as you like.

```javascript
const c = require("ansi-colors");

var gulp = require("gulp");
var beeper = require("beeper");
var log = require("fancy-log");
var spawn = require("child_process").spawn;

gulp.task("retire:watch", ["retire"], function (done) {
  // Watch all javascript files and package.json
  gulp.watch(["js/**/*.js", "package.json"], ["retire"]);
});

gulp.task("retire", function () {
  // Spawn Retire.js as a child process
  // You can optionally add option parameters to the second argument (array)
  var child = spawn("retire", [], { cwd: process.cwd() });

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", function (data) {
    log(data);
  });

  child.stderr.setEncoding("utf8");
  child.stderr.on("data", function (data) {
    log(c.red(data));
    beeper();
  });
});
```



## Donate

<a href="https://www.paypal.me/eoftedal"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif"></a>

Donations will be used to fund the maintainance of the tool and vulnerability repo.
