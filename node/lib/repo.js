/* global require, console, exports */
var utils   = require('./utils'),
    fs      = require('fs'),
    req     = require('request'),
    path    = require('path'),
    log     = require('./utils').log,
    forward   = require('../lib/utils').forwardEvent,
	retire  = require('./retire');
var emitter = require('events').EventEmitter;


function loadJson(url, options) {
	var events = new emitter();
    var request = req;
    var logger = log(options);
	logger.info('Downloading ' + url + ' ...');
	if (options.proxy) {
        request = request.defaults({'proxy' : options.proxy});
    }
    request.get(url, function (error, r, data) {
        if (error) {
            events.emit('stop', 'Error downloading: ' + url, error);
        } else {
            data = options.process ? options.process(data) : data;
            var obj = JSON.parse(data);
            events.emit('done', obj);
        }
    });
	return events;
}

function loadJsonFromFile(file, options) {
    log(options).verbose('Reading ' + file + ' ...');
	var events = new emitter();
    fs.readFile(file, { encoding : 'utf8'}, function(err, data) {
        data = options.process ? options.process(data) : data;
        var obj = JSON.parse(data);
        events.emit('done', obj);
    });
    return events;
}

function loadFromCache(url, cachedir, options) {
    var cacheIndex = path.resolve(cachedir, 'index.json');
    if (!fs.existsSync(cachedir)) fs.mkdirSync(cachedir);
    var cache = fs.existsSync(cacheIndex) ? JSON.parse(fs.readFileSync(cacheIndex)) : {};
    var now = new Date().getTime();
    if (cache[url]) {
        if (now - cache[url].date < 60*60*1000) {
            log(options).info("Loading from cache: " + url);
            return loadJsonFromFile(path.resolve(cachedir, cache[url].file), options);
        } else {
	    if (fs.existsSync(path.resolve(cachedir, cache[url].date + '.json'))) {
            	fs.unlink(path.resolve(cachedir, cache[url].date + '.json'));
	    }	    
        }
    }
    var events = new emitter();
    loadJson(url, options).on('done', function(data) {
        cache[url] = { date : now, file : now + '.json' };
        fs.writeFileSync(path.resolve(cachedir, cache[url].file), JSON.stringify(data), { encoding : 'utf8' });
        fs.writeFileSync(cacheIndex, JSON.stringify(cache), { encoding : 'utf8' });
        events.emit('done', data);
    }).on('stop', forward(events, 'stop'));
    return events;
}

exports.loadrepository = function(repoUrl, options) {
    options = utils.extend(options, { process : retire.replaceVersion });
    if (options.nocache) {
        return loadJson(repoUrl, options);
    }
    return loadFromCache(repoUrl, options.cachedir, options);
};

exports.loadrepositoryFromFile = function(filepath, options) {
    options = utils.extend(options, { process : retire.replaceVersion });
	return loadJsonFromFile(filepath, options);
};
