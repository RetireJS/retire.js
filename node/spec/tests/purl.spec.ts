import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { generatePURL } from '../../lib/reporters/utils';

describe('purl encoding', () => {
  it('should not touch a simple string', () => {
    assert.strictEqual(generatePURL({ component: 'jquery', version: '1.2.3' }), 'pkg:npm/jquery@1.2.3');
  });
  it('should encode @ in package scopes', () => {
    assert.strictEqual(generatePURL({ component: '@angular/core', version: '1.2.3' }), 'pkg:npm/%40angular/core@1.2.3');
  });
  it('should not doulbe encode', () => {
    assert.strictEqual(
      generatePURL({ component: '%40angular/core', version: '1.2.3' }),
      'pkg:npm/%40angular/core@1.2.3',
    );
  });
});
