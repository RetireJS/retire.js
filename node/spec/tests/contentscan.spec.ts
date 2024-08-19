import * as fs from 'fs';
import * as retire from '../../lib/retire';
import * as assert from '../assert';
import * as crypto from 'crypto';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);

const hasher = {
  sha1: function (data: string) {
    const shasum = crypto.createHash('sha1');
    shasum.update(data);
    return shasum.digest('hex');
  },
};

describe('content scan', function () {
  it('should_be_vulnerable_between', function (done) {
    const result = retire.scanFileContent('/*! jQuery v1.8.1 asdasd ', repo, hasher);
    assert.isVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_before', function (done) {
    const result = retire.scanFileContent('/*! jQuery v1.6.1 asdasd ', repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_at', function (done) {
    const result = retire.scanFileContent('/*! jQuery v1.9.0 asdasd ', repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_above', function (done) {
    const result = retire.scanFileContent('/*! jQuery v1.9.1 asdasd ', repo, hasher);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_be_vulnerable_before', function (done) {
    const result = retire.scanFileContent('/*! jQuery v1.4 asdasd ', repo, hasher);
    assert.isVulnerable(result);
    done();
  });
  it('should_be_vulnerable_before_prolog', function (done) {
    const result = retire.scanFileContent('var a = 1; /*! jQuery v1.4 asdasd ', repo, hasher);
    assert.isVulnerable(result);
    done();
  });
});
