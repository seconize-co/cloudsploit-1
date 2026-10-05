var expect = require('chai').expect;
const buildProjectEnvPriviligedMode = require('./buildProjectEnvPriviligedMode');
const codebuildProjectLoggingEnabled = require('./codebuildProjectLoggingEnabled');

// Both plugins build the project ARN from the account id the collector stores under sts.getCallerIdentity.
// They used to read 'STS'/'GetCallerIdentity', which is never set, so every ARN had "null" as the account id.
const cache = {
    sts: {
        getCallerIdentity: { 'us-east-1': { data: '111122223333' } }
    },
    codebuild: {
        listProjects: { 'us-east-1': { data: ['test-project'] } },
        batchGetProjects: {
            'us-east-1': {
                'test-project': {
                    data: {
                        projects: [{
                            name: 'test-project',
                            environment: { privilegedMode: true },
                            logsConfig: { cloudWatchLogs: { status: 'DISABLED' }, s3Logs: { status: 'DISABLED' } }
                        }]
                    }
                }
            }
        }
    }
};

[['buildProjectEnvPriviligedMode', buildProjectEnvPriviligedMode],
 ['codebuildProjectLoggingEnabled', codebuildProjectLoggingEnabled]].forEach(([name, plugin]) => {
    describe(name + ' account id in ARN', function () {
        it('should use the account id from sts getCallerIdentity in the project ARN', function (done) {
            plugin.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].resource).to.equal('arn:aws:codebuild:us-east-1:111122223333:project/test-project');
                done();
            });
        });

        it('should declare STS:getCallerIdentity so the collector fetches it', function () {
            expect(plugin.apis).to.include('STS:getCallerIdentity');
        });
    });
});
