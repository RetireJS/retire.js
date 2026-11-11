import { describe, it } from 'node:test';
import * as fs from 'fs';
import * as nodeAssert from 'node:assert/strict';
import * as retire from '../../lib/retire';
import * as assert from '../assert';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);
// The real repository, since the hash problem depends on the actual extractors and version pattern
const fullRepo = JSON.parse(
  retire.replaceVersion(fs.readFileSync('../repository/jsrepository-v6.json', 'utf8')),
);

describe('filename scan', function () {
  it('should_be_vulnerable_between', function () {
    const result = retire.scanFileName('jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_before', function () {
    const result = retire.scanFileName('jquery-1.6.1.js', repo, false);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_at', function () {
    const result = retire.scanFileName('jquery-1.9.0.js', repo, false);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_above', function () {
    const result = retire.scanFileName('jquery-1.9.1.js', repo, false);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_before', function () {
    const result = retire.scanFileName('jquery-1.4.js', repo, false);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_at_final', function () {
    const result = retire.scanFileName('jquery-1.6.0.js', repo, false);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_at_rc', function () {
    const result = retire.scanFileName('jquery-1.6.0-rc.1.js', repo, false);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_at_patched_rc', function () {
    const result = retire.scanFileName('jquery-1.6.0-rc.1.1.js', repo, false);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_between_linux_path', function () {
    const result = retire.scanFileName('/usr/file/jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
  });
  it('should_be_vulnerable_between_windows_path', function () {
    const result = retire.scanFileName('\\usr\\file\\jquery-1.8.1.js', repo, false);
    assert.isVulnerable(result);
  });
  it('should_be_vulnerable_when_path_matches_uri_linux', function () {
    const result = retire.scanFileName('/usr/file/1.8.1/jquery.js', repo, true);
    assert.isVulnerable(result);
  });
  it('should_be_vulnerable_when_path_matches_uri_win', function () {
    const result = retire.scanFileName('\\usr\\file\\1.8.1\\jquery.js', repo, true);
    assert.isVulnerable(result);
  });
});

describe('filename scan with content hashes in filenames', function () {
  const hashedFileNames = [
    'svelte-890f984e77ad.js',
    'vue-7951fbedcefd.js',
    'vue-7951fbedcefd.min.js',
    'jquery-3e4f5a6b7c8d.js',
    'bootstrap-4f3a2b1c.min.js',
    '/assets/vue-7951fbedcefd.js',
    '\\assets\\svelte-890f984e77ad.js',
  ];
  for (const fileName of hashedFileNames) {
    it(`should_not_interpret_hash_as_version: ${fileName}`, function () {
      const result = retire.scanFileName(fileName, fullRepo, true);
      nodeAssert.deepStrictEqual(
        result.map((r) => `${r.component}@${r.version}`),
        [],
      );
    });
  }

  const versionedFileNames: [string, string, string][] = [
    ['svelte-3.0.0.js', 'svelte', '3.0.0'],
    ['svelte@3.0.0.min.js', 'svelte', '3.0.0'],
    ['vue-2.6.10.js', 'vue', '2.6.10'],
    ['vue-2.6.10.min.js', 'vue', '2.6.10'],
    ['vue-3.0.0-beta.1.js', 'vue', '3.0.0-beta.1'],
    ['jquery-1.12.4.min.js', 'jquery', '1.12.4'],
    ['jquery-3.0.0-rc1.js', 'jquery', '3.0.0-rc1'],
  ];
  for (const [fileName, component, version] of versionedFileNames) {
    it(`should_still_detect_real_version: ${fileName}`, function () {
      const result = retire.scanFileName(fileName, fullRepo, true);
      nodeAssert.deepStrictEqual(
        result.map((r) => `${r.component}@${r.version}`),
        [`${component}@${version}`],
      );
    });
  }
});
