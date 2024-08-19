import * as retire from '../lib/retire';
import { should } from 'chai';
import { Component } from '../lib/types';
should();

export function isVulnerable(results: Component[]) {
  retire.isVulnerable(results).should.equal(true);
}
export function isNotVulnerable(results: Component[]) {
  retire.isVulnerable(results).should.equal(false);
}
