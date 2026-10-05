var expect = require('chai').expect;

// DescribeTrails returns shadow trails by default: a multi-region or organization trail is
// listed in every region, always with its home-region TrailARN and HomeRegion. A trail must
// be reported once, from its home region, not once more per region that lists it.
const plugins = {
    cloudtrailDataEvents: require('./cloudtrailDataEvents'),
    cloudtrailEncryption: require('./cloudtrailEncryption'),
    cloudtrailFileValidation: require('./cloudtrailFileValidation'),
    cloudtrailToCloudwatch: require('./cloudtrailToCloudwatch'),
    cloudtrailDeliveryFailing: require('./cloudtrailDeliveryFailing'),
    cloudtrailManagementEvents: require('./cloudtrailManagementEvents')
};

const trail = (name, homeRegion, extra) => Object.assign({
    Name: name,
    S3BucketName: 'bucket-' + name,
    IncludeGlobalServiceEvents: true,
    IsMultiRegionTrail: true,
    HomeRegion: homeRegion,
    TrailARN: `arn:aws:cloudtrail:${homeRegion || 'us-east-1'}:112233445566:trail/${name}`,
    LogFileValidationEnabled: false,
    IsOrganizationTrail: false
}, extra);

// listed: region -> trails DescribeTrails returns there. Per-trail calls answer in every region.
const createCache = (listed) => {
    const cache = { cloudtrail: { describeTrails: {}, getEventSelectors: {}, getTrailStatus: {} } };
    for (const region of Object.keys(listed)) {
        cache.cloudtrail.describeTrails[region] = listed[region] instanceof Error ? { err: listed[region] } : { data: listed[region] };
        cache.cloudtrail.getEventSelectors[region] = {};
        cache.cloudtrail.getTrailStatus[region] = {};
        for (const t of (Array.isArray(listed[region]) ? listed[region] : [])) {
            cache.cloudtrail.getEventSelectors[region][t.TrailARN] = { data: { EventSelectors: [{ ReadWriteType: 'All', IncludeManagementEvents: true, DataResources: [] }] } };
            cache.cloudtrail.getTrailStatus[region][t.TrailARN] = { data: { IsLogging: true } };
        }
    }
    return cache;
};

const run = (plugin, cache, done, check) => plugin.run(cache, {}, (err, results) => {
    try { check(results); done(); } catch (e) { done(e); }
});
const trailResults = (results) => results.filter(r => r.resource && r.resource.startsWith('arn:aws:cloudtrail:'))
    .map(r => r.region + ' ' + r.resource.split(':trail/')[1]).sort();

for (const [name, plugin] of Object.entries(plugins)) {
    describe(`${name} - trail HomeRegion`, function() {
        it('A: reports a trail listed in its home region', function(done) {
            run(plugin, createCache({ 'ap-south-1': [trail('home', 'ap-south-1')] }), done, (results) => {
                expect(trailResults(results)).to.deep.equal(['ap-south-1 home']);
            });
        });

        it('B: does not report an ap-south-1 trail listed (as a shadow trail) in us-east-1', function(done) {
            run(plugin, createCache({ 'us-east-1': [trail('home', 'ap-south-1')] }), done, (results) => {
                expect(results.length).to.equal(0);
            });
        });

        it('C: does not report a us-east-1 trail listed (as a shadow trail) in ap-south-1', function(done) {
            run(plugin, createCache({ 'ap-south-1': [trail('virginia', 'us-east-1')] }), done, (results) => {
                expect(results.length).to.equal(0);
            });
        });

        it('D: a trail without HomeRegion is reported as before (no guard without the field)', function(done) {
            run(plugin, createCache({ 'us-east-1': [trail('nohome', undefined)], 'ap-south-1': [trail('nohome', undefined)] }), done, (results) => {
                expect(trailResults(results)).to.deep.equal(['ap-south-1 nohome', 'us-east-1 nohome']);
            });
        });

        it('D: region-level results are unchanged (no trails / query error); no "global" region is produced', function(done) {
            run(plugin, createCache({ 'us-east-1': [], 'ap-south-1': new Error('AccessDenied') }), done, (results) => {
                const byRegion = Object.fromEntries(results.map(r => [r.region, r]));
                expect(results.length).to.equal(2);
                expect(byRegion['ap-south-1'].status).to.equal(3);
                expect(byRegion['ap-south-1'].resource).to.not.be.ok;
                expect(byRegion['us-east-1'].resource).to.not.be.ok;
                expect(results.some(r => r.region === 'global')).to.equal(false);
            });
        });

        it('D: a multi-region trail logging global service events is still reported once, in its home region', function(done) {
            const global = trail('org-global', 'ap-south-1', { IncludeGlobalServiceEvents: true, IsMultiRegionTrail: true, IsOrganizationTrail: true });
            run(plugin, createCache({ 'us-east-1': [global], 'ap-south-1': [global], 'eu-west-1': [global] }), done, (results) => {
                expect(trailResults(results)).to.deep.equal(['ap-south-1 org-global']);
            });
        });

        it('E: in one region, reports the trail homed there and skips the other region\'s trail', function(done) {
            run(plugin, createCache({ 'ap-south-1': [trail('a', 'ap-south-1'), trail('b', 'us-east-1')] }), done, (results) => {
                expect(trailResults(results)).to.deep.equal(['ap-south-1 a']);
            });
        });

        it('F: InnovationUAT shape - trails listed in us-east-1 first, then ap-south-1, are reported only from ap-south-1', function(done) {
            const s3events = trail('s3-events', 'ap-south-1');
            const baseline = trail('aws-controltower-BaselineCloudTrail', 'ap-south-1', { IsOrganizationTrail: true,
                TrailARN: 'arn:aws:cloudtrail:ap-south-1:358897053974:trail/aws-controltower-BaselineCloudTrail' });
            run(plugin, createCache({ 'us-east-1': [baseline, s3events], 'ap-south-1': [baseline, s3events] }), done, (results) => {
                expect(trailResults(results)).to.deep.equal(['ap-south-1 aws-controltower-BaselineCloudTrail', 'ap-south-1 s3-events']);
                for (const r of results) expect(r.resource.split(':')[3]).to.equal(r.region);
            });
        });
    });
}
