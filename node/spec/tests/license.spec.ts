import * as license from '../../lib/license';
import { should } from 'chai';
should();

describe('licenses', function () {
  it('should_work_for_single_license', function (done) {
    const licenses = license.evaluateLicense(['MIT >=0'], '1.0.0');
    licenses.length.should.equal(1);
    licenses[0].should.equal('MIT');
    done();
  });
  it('should_not_find_single_license', function (done) {
    const licenses = license.evaluateLicense(['MIT >=2.0.0'], '1.0.0');
    licenses.length.should.equal(0);
    done();
  });
  it('should_find_correct_license_when_multiple', function (done) {
    const licenses = license.evaluateLicense(['MIT >=2.0.0', 'GPL-2.0 >=0 <2.0.0'], '1.0.0');
    licenses.length.should.equal(1);
    licenses[0].should.equal('GPL-2.0');
    done();
  });
  it('should_work_with_license_expression', function (done) {
    const licenses = license.evaluateLicense(['MIT >=2.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0'], '1.0.0');
    licenses.length.should.equal(1);
    licenses[0].should.equal('GPL-2.0 OR MIT');
    done();
  });
  it('should_work_with_license_expression', function (done) {
    const licensesA = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '1.0.0');
    licensesA.length.should.equal(1);
    licensesA[0].should.equal('GPL-2.0 OR MIT');
    const licensesB = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '2.5.0');
    licensesB.length.should.equal(1);
    licensesB[0].should.equal('MIT');
    const licensesC = license.evaluateLicense(['MIT >=2.0.0 <3.0.0', '(GPL-2.0 OR MIT) >=0 <2.0.0;>=3.0.0'], '4.0.0');
    licensesC.length.should.equal(1);
    licensesC[0].should.equal('GPL-2.0 OR MIT');
    done();
  });
});
