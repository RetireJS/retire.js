const repo = require("./repo");

exports["test download repo"] = function(assert, done) {
  repo.download().then(() => {
    let repository = repo.getRepository();
    assert.ok(repository != null, "There should be a repo object");
    assert.ok(Object.keys(repository).length > 0, "There should be more than 0 repo components");
    done();
  });
};

require("sdk/test").run(exports);