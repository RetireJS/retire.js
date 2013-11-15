const repo = require("./repo");

exports["test download repo"] = function(assert, done) {
  repo.download().then(() => {
    let repository = repo.getRepository();
    assert.ok(repository != null, true);
    assert.ok(Object.keys(repository).length > 0, true);
    done();
  });
};

require("sdk/test").run(exports);