import * as fs from 'fs';
import * as retire from '../../lib/retire';
import * as assert from '../assert';
import * as crypto from 'crypto';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);
const content = 'data';

const hasher = {
  sha1: function (data: string) {
    const shasum = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  },
};

const hash = hasher.sha1(content);
describe('hash scan', function () {
  it('should_be_vulnerable_between', function (done) {
    repo.jquery.extractors.hashes[hash] = '1.8.1';
    const result = retire.scanFileContent(content, repo, hasher);
    assert.isVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_before', function (done) {
    repo.jquery.extractors.hashes[hash] = '1.6.1';
    const result = retire.scanFileContent(content, repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_at', function (done) {
    repo.jquery.extractors.hashes[hash] = '1.9.0';
    const result = retire.scanFileContent(content, repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_above', function (done) {
    repo.jquery.extractors.hashes[hash] = '1.9.1';
    const result = retire.scanFileContent(content, repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_be_vulnerable_before', function (done) {
    repo.jquery.extractors.hashes[hash] = '1.4';
    const result = retire.scanFileContent(content, repo, hasher);
    assert.isVulnerable(result);
    done();
  });
});
