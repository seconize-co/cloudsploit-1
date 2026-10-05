var expect = require('chai').expect;
var helpers = require('./index');

// helpers.regions(settings) narrows every service's region list to settings.region (--region).
describe('helpers.regions - region selection', function() {
    it('returns the full catalog when no region is selected', function() {
        var all = helpers.regions({});
        expect(all.ec2).to.include('us-east-1');
        expect(all.ec2).to.include('ap-south-1');
    });

    it('limits regional services to the selected regions', function() {
        var r = helpers.regions({ region: ['ap-south-1'] });
        expect(r.ec2).to.deep.equal(['ap-south-1']);
        expect(r.cloudtrail).to.deep.equal(['ap-south-1']);
    });

    it('keeps global services unfiltered', function() {
        var r = helpers.regions({ region: ['ap-south-1'] });
        expect(r.iam).to.deep.equal(helpers.regions({}).iam);
        expect(r.s3).to.deep.equal(helpers.regions({}).s3);
    });

    it('keeps STS (account id for ARNs) in the default region even when it is not selected', function() {
        var r = helpers.regions({ region: ['ap-south-1'] });
        expect(r.sts).to.deep.equal(['us-east-1']);
        expect(r.sts).to.include(helpers.defaultRegion({}));
    });

    it('keeps account-level Shield and Organizations in the default region even when it is not selected', function() {
        var r = helpers.regions({ region: ['ap-south-1'] });
        expect(r.shield).to.deep.equal(['us-east-1']);
        expect(r.organizations).to.deep.equal(['us-east-1']);
    });

    it('exempts the collector service names of the always-collected services', function() {
        expect(helpers.alwaysCollectedServices).to.include.members(['STS', 'Shield', 'Organizations']);
        var api = require('./api');
        helpers.alwaysCollectedServices.forEach(function(s) { expect(api.calls).to.have.property(s); });
    });
});
