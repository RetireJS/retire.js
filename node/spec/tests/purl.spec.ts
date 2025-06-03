import { should } from 'chai';
should();
import { generatePURL } from '../../lib/reporters/utils';

describe('purl encoding', () => {
  it('should not touch a simple string', () => {
    generatePURL({ component: 'jquery', version: '1.2.3' }).should.equal('pkg:npm/jquery@1.2.3');
  });
  it('should encode @ in package scopes', () => {
    generatePURL({ component: '@angular/core', version: '1.2.3' }).should.equal('pkg:npm/%40angular/core@1.2.3');
  });
  it('should not doulbe encode', () => {
    generatePURL({ component: '%40angular/core', version: '1.2.3' }).should.equal('pkg:npm/%40angular/core@1.2.3');
  });
});
