/* global require, exports */
/*jshint esversion: 6 */
var utils   = require('./utils'),
    fs      = require('fs'),
    path    = require('path'),
    forward = require('../lib/utils').forwardEvent,
    http    = require('http'),
    https   = require('https'),
    retire  = require('./retire'),
    URL     = require('url'),
    ProxyAgent = require('proxy-agent');

var emitter = require('events').EventEmitter;


function loadJson(url, options) {
  var events = new emitter();
  options.log.info('Downloading ' + url + ' ...');
  var reqOptions = Object.assign({}, URL.parse(url), { method: 'GET' });
  var proxyUri = options.proxy || process.env.http_proxy;
  if (proxyUri) {
    reqOptions.agent = new ProxyAgent(proxyUri);
  }
  if (options.insecure) {
    reqOptions.rejectUnauthorized = false;
  }
  if (options.cacertbuf) {
    reqOptions.ca = [ options.cacertbuf ];
  }
  var req = (url.startsWith("http:") ? http : https).get(reqOptions, function (res) {
    if (res.statusCode != 200) return events.emit('stop', 'Error downloading: ' + url + ": HTTP " + res.statusCode + " " + res.statusText);
    var data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {
        var d = Buffer.concat(data).toString();
        d = options.process ? options.process(d) : d;
        events.emit('done', JSON.parse(d));
    });
  });
  req.on('error', e => events.emit('stop', 'Error downloading: ' + url + ": " + e.toString()));
  req.end();
  return events;
}

function loadJsonFromFile(file, options) {
  options.log.debug('Reading ' + file + ' ...');
  var events = new emitter();
  fs.readFile(file, { encoding : 'utf8'}, function(err, data) {
    if (err) { return events.emit('stop', err.toString()); }
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
      options.log.info('Loading from cache: ' + url);
      return loadJsonFromFile(path.resolve(cachedir, cache[url].file), options);
    } else {
      if (fs.existsSync(path.resolve(cachedir, cache[url].date + '.json'))) {
        try {
          fs.unlinkSync(path.resolve(cachedir, cache[url].date + '.json'));
        } catch (error) {
          if (error.code !== 'ENOENT') {
            throw error;
          } else {
            console.warn("Could not delete cache. Ignore this error if you are running multiple retire.js in parallel");
          }
        }
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

exports.asbowerrepo = function(jsRepo) {
  var result = {};
  Object.keys(jsRepo).map(function(k) {
    (jsRepo[k].bowername || [k]).map(function(b) {
      result[b] = result[b] || { vulnerabilities: [] };
      result[b].vulnerabilities = result[b].vulnerabilities.concat(jsRepo[k].vulnerabilities);
    });
  });
  return result;
};

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
