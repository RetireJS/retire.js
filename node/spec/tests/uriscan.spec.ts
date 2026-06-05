import { describe, it } from 'node:test';
import * as fs from 'fs';
import * as assert from '../assert';
import * as retire from '../../lib/retire';

const data = fs.readFileSync('spec/repository.json', 'utf8');
const repo = JSON.parse(data);

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
