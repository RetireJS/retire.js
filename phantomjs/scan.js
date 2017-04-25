try {
    var info = {},
        jsContentTypes = ['application/x-javascript', 'application/javascript', 'text/javascript'],
        fs = require('fs'),
        noop = function () {},
        page,
        url,
        retire,
        repo,
        pageTimeoutTimerId;

    url = require('system').args[1];

    if (!url) {
        throw 'Usage: phantomjs ' + require('system').args[0] + ' <url>';
    }

    retire = require('../node/lib/retire');

    repo = JSON.parse(retire.replaceVersion(fs.read('../repository/jsrepository.json')));

    page = require('webpage').create();

    page.onResourceReceived = function (response) {
        var isJsFile = jsContentTypes.some(function(type) {
            return response.contentType.indexOf(type) > -1;
        });

        if (isJsFile) {
            var scaned = retire.scanUri(response.url, repo);

            if (scaned = scaned[0]) info[scaned.component] = scaned;
        }
    };

    // dont send page logs and errors to output
    page.onConsoleMessage = noop;
    page.onError = noop;
    page.onResourceError = noop;

    var timeoutMs = 15000;

    var pageTimeoutTimerId = setTimeout(function() {
        page.close();
        console.error('{"error": "timeout"}');
        phantom.exit(1);
    }, timeoutMs);

    page.open(url, function (status) {
        clearTimeout(pageTimeoutTimerId);

        if (status === 'fail') {
            console.error('{"error": "Page load fail"}');
            page.close();
            phantom.exit(1);
        }

        Object.keys(repo).forEach(function (componentName) {
            var component = repo[componentName];

            component.extractors.func && component.extractors.func.forEach(function (func) {
                var version = page.evaluateJavaScript('(function(){return ' + func + ';})');

                if (version) {
                    var res = retire.check(componentName, version, repo);

                    if (res = res[0]) info[componentName] = res;
                }
            });
        });

        delete info['dont check'];

        // output
        console.log(JSON.stringify(info, null, 4));

        phantom.exit();
    });

} catch (e) {
    console.error(e);

    phantom.exit(1);
}
