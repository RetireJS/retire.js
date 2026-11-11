import { describe, it } from 'node:test';
import * as fs from 'fs';
import * as nodeAssert from 'node:assert/strict';
import * as assert from '../assert';
import * as retire from '../../lib/retire';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);
// The real repository, since the hash problem depends on the actual extractors and version pattern
const fullRepo = JSON.parse(
  retire.replaceVersion(fs.readFileSync('../repository/jsrepository-v6.json', 'utf8')),
);

describe('url scan', function () {
  it('should_be_vulnerable_between', function () {
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.8.1/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
  it('should_not_be_vulnerable_before', function () {
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_at', function () {
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_not_be_vulnerable_above', function () {
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.9.1/jquery.min.js', repo);
    assert.isNotVulnerable(result);
  });
  it('should_be_vulnerable_before', function () {
    const result = retire.scanUri('https://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js', repo);
    assert.isVulnerable(result);
  });
});

describe('url scan with content hashes in urls', function () {
  const hashedUris = [
    'https://example.com/assets/svelte-890f984e77ad.js',
    'https://example.com/assets/vue-7951fbedcefd.js',
    'https://example.com/_app/immutable/chunks/svelte-890f984e77ad.js',
    'https://example.com/svelte@890f984e77ad/index.js',
    'https://example.com/npm/vue@7951fbedcefd',
    'https://example.com/vue/7951fbedcefd/vue.min.js',
    'https://example.com/7951fbedcefd/jquery.min.js',
  ];
  for (const uri of hashedUris) {
    it(`should_not_interpret_hash_as_version: ${uri}`, function () {
      const result = retire.scanUri(uri, fullRepo);
      nodeAssert.deepStrictEqual(
        result.map((r) => `${r.component}@${r.version}`),
        [],
      );
    });
  }

  const versionedUris: [string, string, string][] = [
    ['https://cdn.jsdelivr.net/npm/svelte@3.0.0/index.mjs', 'svelte', '3.0.0'],
    ['https://cdn.jsdelivr.net/npm/vue@2.6.10', 'vue', '2.6.10'],
    ['https://cdn.jsdelivr.net/npm/vue@3.0.0-beta.1', 'vue', '3.0.0-beta.1'],
    ['https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.10/vue.min.js', 'vue', '2.6.10'],
    ['https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js', 'jquery', '1.12.4'],
  ];
  for (const [uri, component, version] of versionedUris) {
    it(`should_still_detect_real_version: ${uri}`, function () {
      const result = retire.scanUri(uri, fullRepo);
      nodeAssert.deepStrictEqual(
        result.map((r) => `${r.component}@${r.version}`),
        [`${component}@${version}`],
      );
    });
  }
});
