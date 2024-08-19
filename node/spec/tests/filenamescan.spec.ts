import * as fs from 'fs';
import * as retire from '../../lib/retire';
import * as assert from '../assert';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);

describe('filename scan', function () {
  it('should_be_vulnerable_between', function (done) {
    const result = retire.scanFileName('jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_before', function (done) {
    const result = retire.scanFileName('jquery-1.6.1.js', repo, false);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_at', function (done) {
    const result = retire.scanFileName('jquery-1.9.0.js', repo, false);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_above', function (done) {
    const result = retire.scanFileName('jquery-1.9.1.js', repo, false);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_be_vulnerable_before', function (done) {
    const result = retire.scanFileName('jquery-1.4.js', repo, false);
    assert.isVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_at_final', function (done) {
    const result = retire.scanFileName('jquery-1.6.0.js', repo, false);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_be_vulnerable_at_rc', function (done) {
    const result = retire.scanFileName('jquery-1.6.0-rc.1.js', repo, false);
    assert.isVulnerable(result);
    done();
  });
  it('should_not_be_vulnerable_at_patched_rc', function (done) {
    const result = retire.scanFileName('jquery-1.6.0-rc.1.1.js', repo, false);
    assert.isNotVulnerable(result);
    done();
  });
  it('should_be_vulnerable_between_linux_path', function (done) {
    const result = retire.scanFileName('/usr/file/jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
    done();
  });
  it('should_be_vulnerable_between_windows_path', function (done) {
    const result = retire.scanFileName('\\usr\\file\\jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
    done();
  });
  it('should_be_vulnerable_when_path_matches_uri_linux', function (done) {
    const result = retire.scanFileName('/usr/file/1.8.1/jquery.js', repo, true);
    assert.isVulnerable(result);
    done();
  });
  it('should_be_vulnerable_when_path_matches_uri_win', function (done) {
    const result = retire.scanFileName('\\usr\\file\\1.8.1\\jquery.js', repo, true);
    assert.isVulnerable(result);
    done();
  });
});
