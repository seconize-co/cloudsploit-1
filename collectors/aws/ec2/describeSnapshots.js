var AWS = require('aws-sdk');

// This call must be overridden because the
// default call retrieves every snapshot
// available, including public ones

module.exports = function(AWSConfig, collection, callback) {
    var ec2 = new AWS.EC2(AWSConfig);

    // The account ID is already collected once by STS:getCallerIdentity
    // (main calls phase, which always completes before this postcalls entry
    // runs). Reuse it instead of making a fresh STS call in every EC2 region.
    var accountId;
    if (collection.sts && collection.sts.getCallerIdentity) {
        for (var stsRegion in collection.sts.getCallerIdentity) {
            if (collection.sts.getCallerIdentity[stsRegion] &&
                collection.sts.getCallerIdentity[stsRegion].data) {
                accountId = collection.sts.getCallerIdentity[stsRegion].data;
                break;
            }
        }
    }

    if (!accountId) {
        collection.ec2.describeSnapshots[AWSConfig.region].err = 'Unable to filter by owner ID';
        return callback();
    }

    var params = {
        Filters: [
            {
                Name: 'owner-id',
                Values: [
                    accountId
                ]
            },
            {
                Name: 'status',
                Values: [
                    'completed'
                ]
            }
        ]
    };

    ec2.describeSnapshots(params, function(err, data){
        if (err) {
            collection.ec2.describeSnapshots[AWSConfig.region].err = err;
        } else {
            collection.ec2.describeSnapshots[AWSConfig.region].data = data.Snapshots;
        }

        callback();
    });
};
