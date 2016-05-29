/* global require, console, exports */
var _       = require('lodash'),
    fs      = require('fs'),
    https     = require('https'),
    path    = require('path'),
    log     = require('./utils').log,
    forward   = require('../lib/utils').forwardEvent,
	retire  = require('./retire');
var emitter = require('events').EventEmitter;


function loadJson(url, options) {
	var events = new emitter();
    var logger = log(options);
	logger.info('Downloading ' + url + ' ...');
    https.get(url, function (res) {
        var json = '';
        res.on('data', function (data) {
            json += data.toString();
        });
        res.on('end', function () {
            events.emit('done', JSON.parse(options.process ? options.process(json) : json));
        });
    }).on('error', function (error) {
        events.emit('stop', 'Error downloading: ' + url, error);
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
            fs.unlink(path.resolve(cachedir, cache[url].date + '.json'));
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
    options = _.extend(options, { process : retire.replaceVersion });
    if (options.nocache) {
        return loadJson(repoUrl, options);
    }
    return loadFromCache(repoUrl, options.cachedir, options);
};

exports.loadrepositoryFromFile = function(filepath, options) {
    options = _.extend(options, { process : retire.replaceVersion });
	return loadJsonFromFile(filepath, options);
};