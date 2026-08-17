var expect = require('chai').expect;
const crossVpcPublicPrivate = require('./crossVpcPublicPrivate');

const describeSubnets = [
    {
        "SubnetId": "subnet-public-1",
        "VpcId": "vpc-1",
        "CidrBlock": "10.0.1.0/24"
    },
    {
        "SubnetId": "subnet-private-1",
        "VpcId": "vpc-2",
        "CidrBlock": "10.0.2.0/24"
    }
];

const describeRouteTables = [
    {
        "RouteTableId": "rtb-public",
        "Routes": [
            {
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": "igw-0123456789"
            },
            {
                "DestinationCidrBlock": "10.0.2.0/24",
                "VpcPeeringConnectionId": "pcx-1"
            }
        ],
        "Associations": [
            { "SubnetId": "subnet-public-1" }
        ]
    },
    {
        "RouteTableId": "rtb-private",
        "Routes": [
            {
                "DestinationCidrBlock": "10.0.1.0/24",
                "VpcPeeringConnectionId": "pcx-1"
            }
        ],
        "Associations": [
            { "SubnetId": "subnet-private-1" }
        ]
    }
];

const describeVpcPeeringConnections = [
    {
        "VpcPeeringConnectionId": "pcx-1",
        "AccepterVpcInfo": {
            "VpcId": "vpc-1",
            "CidrBlock": "10.0.1.0/24",
            "OwnerId": "111111111111"
        },
        "RequesterVpcInfo": {
            "VpcId": "vpc-2",
            "CidrBlock": "10.0.2.0/24",
            "OwnerId": "222222222222"
        }
    }
];

const createCache = (subnetsData, subnetsErr, routeTablesData, peeringData) => {
    return {
        ec2: {
            describeSubnets: {
                'us-east-1': {
                    data: subnetsData,
                    err: subnetsErr
                }
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTablesData
                }
            },
            describeVpcPeeringConnections: {
                'us-east-1': {
                    data: peeringData
                }
            }
        }
    };
};

describe('crossVpcPublicPrivate', function () {
    describe('run', function () {
        it('should UNKNOWN if unable to query for Subnets', function (done) {
            const cache = createCache(null, { message: 'Access Denied' });
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Subnets');
                done();
            });
        });

        it('should PASS if real subnet data is present but no VPC peering connections exist', function (done) {
            const cache = createCache(describeSubnets, null, describeRouteTables, []);
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No public private subnets connection found');
                done();
            });
        });

        it('should FAIL if a route between public and private subnets of different VPCs is found', function (done) {
            const cache = createCache(describeSubnets, null, describeRouteTables, describeVpcPeeringConnections);
            crossVpcPublicPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('A route between public and private subnets of different VPCs found');
                done();
            });
        });
    });
});
