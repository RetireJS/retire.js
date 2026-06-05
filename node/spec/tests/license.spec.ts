import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as license from '../../lib/license';

describe('licenses', function () {
  it('should_work_for_single_license', function () {
    const licenses = license.evaluateLicense(['MIT >=0'], '1.0.0');
    assert.strictEqual(licenses.length, 1);
    assert.strictEqual(licenses[0], 'MIT');
  });
  it('should_not_find_single_license', function () {
    const licenses = license.evaluateLicense(['MIT >=2.0.0'], '1.0.0');
    assert.strictEqual(licenses.length, 0);
  });
  it('should_find_correct_license_when_multiple', function () {
    const licenses = license.evaluateLicense(['MIT >=2.0.0', 'GPL-2.0 >=0 <2.0.0'], '1.0.0');
    assert.strictEqual(licenses.length, 1);
    assert.strictEqual(licenses[0], 'GPL-2.0');
  });
  it('should_work_with_license_expression', function () {
    const licenses = license.evaluateLicense(['MIT >=2.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0'], '1.0.0');
    assert.strictEqual(licenses.length, 1);
    assert.strictEqual(licenses[0], 'GPL-2.0 OR MIT');
  });
  it('should_work_with_license_expression', function () {
    const licensesA = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '1.0.0');
    assert.strictEqual(licensesA.length, 1);
    assert.strictEqual(licensesA[0], 'GPL-2.0 OR MIT');
    const licensesB = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '2.5.0');
    assert.strictEqual(licensesB.length, 1);
    assert.strictEqual(licensesB[0], 'MIT');
    const licensesC = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '4.0.0');
    assert.strictEqual(licensesC.length, 1);
    assert.strictEqual(licensesC[0], 'GPL-2.0 OR MIT');
  });
});
