var expect = require('chai').expect;

// These plugins built the snapshot ARN without the service ("arn:aws:<region>:<account>:snapshot/<id>").
// A snapshot ARN is arn:aws:ec2:<region>:<account>:snapshot/<id>, as ebsEncryptedSnapshots already builds it.
const ARN = 'arn:aws:ec2:us-east-1:111122223333:snapshot/snap-0123456789abcdef0';
const snapshot = {
    SnapshotId: 'snap-0123456789abcdef0',
    OwnerId: '111122223333',
    StartTime: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    VolumeId: 'vol-0123456789abcdef0',
    Tags: []
};
const cache = {
    sts: { getCallerIdentity: { 'us-east-1': { data: '111122223333' } } },
    ec2: {
        describeSnapshots: { 'us-east-1': { data: [snapshot] } },
        describeSnapshotAttribute: { 'us-east-1': { [snapshot.SnapshotId]: { data: { CreateVolumePermissions: [{ Group: 'all' }] } } } }
    }
};

['ebsOldSnapshots', 'ebsRecentSnapshots', 'ebsSnapshotHasTags', 'ebsSnapshotPublic'].forEach((name) => {
    describe(name + ' snapshot ARN', function () {
        it('should report the snapshot as arn:aws:ec2:<region>:<account>:snapshot/<id>', function (done) {
            require('./' + name).run(cache, {}, (err, results) => {
                const resources = results.filter(r => r.resource && r.resource !== 'N/A').map(r => r.resource);
                expect(resources).to.not.be.empty;
                resources.forEach(r => expect(r).to.equal(ARN));
                done();
            });
        });
    });
});
