/*jshint esversion: 6 */

var retire = require('./retire');
var utils = require('./utils');
var fs = require('fs');
var crypto = require('crypto');

var loggers = {
  console  : require("./reporters/console"),
  json     : require("./reporters/json"),
  depcheck : require("./reporters/depcheck"),
  cyclonedx: require("./reporters/cyclonedx")
};



var colorwarn = function(x) { return x; };

var verbose = false;

function hashContent(hash, content) {
  var h = crypto.createHash(hash);
  h.update(content);
  return h.digest('hex'); 
}

var hash = {
  md5: (file) => hashContent('md5', file),
  sha1: (file) => hashContent('sha1', file),
  sha256: (file) => hashContent('sha256', file),
  sha512: (file) => hashContent('sha512', file),
};



var writer = {
  out: console.log,
  err: function(x) { console.warn(colorwarn(x)); },
  close : function(callback) { 
    process.stderr.on('drain', function() {
      process.stderr.on('drain', function() {
        callback();
      });
    });
  }
};

var logger = {
  info : function(x) { writer.out(x); },
  debug : function(x) { if (verbose) writer.out(x); },
  warn : function(x) { writer.err(x); },
  error : function(x) { writer.err(x); },

  logDependency : function(finding) { },
  logVulnerableDependency: function(finding) { },
  close: function(callback) { writer.close(callback); }
};



function configureFileWriter(config) {
  var fileOutput = {
    fileDescriptor: fs.openSync(config.outputpath, "w")
  };
  if (fileOutput.fileDescriptor < 0) {
    console.error("Could not open " + config.outputpath + " for writing");
    process.exit(9);
  } 
  fileOutput.stream = fs.createWriteStream('', {fd: fileOutput.fileDescriptor});
  var writeToFile = function(message) {
    fileOutput.stream.write(message);
    fileOutput.stream.write('\n');
  };
  writer.out = writer.err = writeToFile;
  writer.close = function(callback) {
    fileOutput.stream.on('finish', function() {
      fs.close(fileOutput.fileDescriptor);
      callback();
    });
    fileOutput.stream.end();
  };
}




exports.open = function(config) {
  verbose = config.verbose;
  if (config.colors) colorwarn = config.colorwarn;
  var format = config.outputformat || "console";
  if (Object.keys(loggers).indexOf(format) == -1) {
    console.warn("Invalid outputformat: " + format);
    process.exit(1);
  }
  loggers[format].configure(logger, writer, config, hash);

  if (typeof config.outputpath === 'string') { 
    configureFileWriter(config); 
  }
  return logger;
};
