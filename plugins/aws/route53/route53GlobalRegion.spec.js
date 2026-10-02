var expect = require('chai').expect;

// Route53 is a global service. Its data is collected in the default region (us-east-1), but the
// results must be labelled 'global', like the Route53 Domains, IAM and CloudFront plugins, so a scan
// limited to other regions does not discard them as us-east-1 results.
const plugins = {
    route53InUse: require('./route53InUse'),
    danglingDnsRecords: require('./danglingDnsRecords'),
    senderPolicyFwInUse: require('./senderPolicyFwInUse'),
    senderPolicyFwRecordPresent: require('./senderPolicyFwRecordPresent')
};

const ZONE = '/hostedzone/Z0001';
const createCache = (zones, recordSets, extra) => Object.assign({
    route53: {
        listHostedZones: { 'us-east-1': zones },
        listResourceRecordSets: { 'us-east-1': { [ZONE]: recordSets } }
    },
    s3: { listBuckets: { 'us-east-1': { data: [] } } },
    ec2: { describeAddresses: { 'ap-south-1': { data: [] } } }
}, extra);

const run = (plugin, cache, done, check) => plugin.run(cache, {}, (err, results) => {
    try { check(results); done(); } catch (e) { done(e); }
});

const zones = { data: [{ Id: ZONE, Name: 'example.com.' }] };
const records = { data: { ResourceRecordSets: [{ Name: 'www.example.com.', Type: 'A', ResourceRecords: [{ Value: '203.0.113.10' }] },
    { Name: 'example.com.', Type: 'TXT', ResourceRecords: [{ Value: '"v=spf1 -all"' }] }] } };

for (const [name, plugin] of Object.entries(plugins)) {
    describe(`${name} - region label`, function() {
        it('labels hosted zone results global', function(done) {
            run(plugin, createCache(zones, records), done, (results) => {
                expect(results.length).to.be.above(0);
                for (const r of results) expect(r.region).to.equal('global');
            });
        });

        it('labels "unable to query hosted zones" global', function(done) {
            run(plugin, createCache({ err: { message: 'AccessDenied' } }, records), done, (results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('global');
            });
        });

        it('labels "no hosted zones" global', function(done) {
            run(plugin, createCache({ data: [] }, records), done, (results) => {
                expect(results.length).to.equal(1);
                expect(results[0].region).to.equal('global');
            });
        });

        it('still reads hosted zones from the default region cache', function(done) {
            const cache = createCache(zones, records);
            cache.route53.listHostedZones = { 'ap-south-1': zones };   // nothing in us-east-1
            run(plugin, cache, done, (results) => {
                expect(results.length).to.equal(0);
            });
        });
    });
}

describe('danglingDnsRecords - per-region Elastic IP lookups keep their region', function() {
    it('labels an Elastic IP query failure with the region that failed', function(done) {
        const cache = createCache(zones, records, { ec2: { describeAddresses: { 'ap-south-1': { err: { message: 'AccessDenied' } } } } });
        run(plugins.danglingDnsRecords, cache, done, (results) => {
            const eip = results.filter(r => r.message.indexOf('elastic IP') > -1);
            expect(eip.map(r => r.region)).to.deep.equal(['ap-south-1']);
            const zone = results.filter(r => r.resource === 'arn:aws:route53:::' + ZONE);
            expect(zone.length).to.equal(1);
            expect(zone[0].region).to.equal('global');
            expect(zone[0].status).to.equal(2);   // 203.0.113.10 is not an Elastic IP of the account
        });
    });
});
