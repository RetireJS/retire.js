import * as retire from '../lib/retire';
import * as assert from 'node:assert';
import { Component } from '../lib/types';

export function isVulnerable(results: Component[]) {
  assert.strictEqual(retire.isVulnerable(results), true);
}
export function isNotVulnerable(results: Component[]) {
  assert.strictEqual(retire.isVulnerable(results), false);
}
