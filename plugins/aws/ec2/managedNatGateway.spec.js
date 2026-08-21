var expect = require('chai').expect;
const managedNatGateway = require('./managedNatGateway');

const describeVpcs = [
    {
        "CidrBlock": "172.31.0.0/16",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-35ef2d5a",
                "CidrBlock": "172.31.0.0/16",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": true
    },
    {
        "CidrBlock": "10.0.0.0/24",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "VpcId": "vpc-0b739af479bea9bff",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-017f349579cad8c30",
                "CidrBlock": "10.0.0.0/24",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": false,
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-vpc"
            }
        ]
    },
    {
        "CidrBlock": "10.1.0.0/24",
        "DhcpOptionsId": "dopt-3a821040",
        "State": "available",
        "VpcId": "vpc-nat-instance-11111",
        "OwnerId": "111122223333",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [],
        "IsDefault": false
    }
]

const describeNatGateways = [
    {
        "CreateTime": "2020-10-22T03:52:03.000Z",
        "NatGatewayAddresses": [
            {
                "AllocationId": "eipalloc-012a1de6c78e459ba",
                "NetworkInterfaceId": "eni-0e1f6ede5831b878c",
                "PrivateIp": "172.31.50.47",
                "PublicIp": "52.73.207.255"
            }
        ],
        "NatGatewayId": "nat-042a6ab635c627c61",
        "State": "available",
        "SubnetId": "subnet-6a8b635b",
        "VpcId": "vpc-99de2fe4",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-65"
            }
        ]
    }
];

const describeRouteTables = [
    {
        "RouteTableId": "rtb-empty",
        "VpcId": "vpc-0b739af479bea9bff",
        "Routes": []
    },
    {
        "RouteTableId": "rtb-nat-instance",
        "VpcId": "vpc-nat-instance-11111",
        "Routes": [
            {
                "DestinationCidrBlock": "0.0.0.0/0",
                "InstanceId": "i-natinstance111",
                "Origin": "CreateRoute",
                "State": "active"
            }
        ]
    },
    {
        "RouteTableId": "rtb-nonexistent-instance",
        "VpcId": "vpc-0b739af479bea9bff",
        "Routes": [
            {
                "DestinationCidrBlock": "0.0.0.0/0",
                "InstanceId": "i-doesnotexist",
                "Origin": "CreateRoute",
                "State": "blackhole"
            }
        ]
    }
];

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "InstanceId": "i-natinstance111",
                "InstanceType": "t3.micro",
                "State": {
                    "Code": 16,
                    "Name": "running"
                },
                "SourceDestCheck": false,
                "VpcId": "vpc-nat-instance-11111"
            }
        ]
    },
    {
        "Groups": [],
        "Instances": [
            {
                "InstanceId": "i-regularinstance",
                "InstanceType": "t3.micro",
                "State": {
                    "Code": 16,
                    "Name": "running"
                },
                "SourceDestCheck": true,
                "VpcId": "vpc-0b739af479bea9bff"
            }
        ]
    },
    {
        "Groups": [],
        "Instances": [
            {
                "InstanceId": "i-terminatednatinstance",
                "InstanceType": "t3.micro",
                "State": {
                    "Code": 48,
                    "Name": "terminated"
                },
                "SourceDestCheck": false,
                "VpcId": "vpc-0b739af479bea9bff"
            }
        ]
    }
];

const createCache = (vpc, nat, routeTables, instances) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpc
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    data: nat
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                },
            },
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    err: {
                        message: 'error describing VPCs'
                    },
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing NAT Gateways'
                    },
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    err: {
                        message: 'error describing route tables'
                    },
                },
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
        },
    };
};

const createRouteTablesErrorCache = (vpc, nat) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpc
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    data: nat
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    err: {
                        message: 'error describing route tables'
                    },
                },
            },
            describeInstances: {
                'us-east-1': {
                    data: []
                },
            },
        },
    };
};

const createInstancesErrorCache = (vpc, nat, routeTables) => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': {
                    data: vpc
                },
            },
            describeNatGateways: {
                'us-east-1': {
                    data: nat
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
                },
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeVpcs: {
                'us-east-1': null,
            },
            describeNatGateways: {
                'us-east-1': null,
            },
        },
    };
};


describe('managedNatGateway', function () {
    describe('run', function () {
        it('should PASS if VPC is using managed NAT gateway', function (done) {
            const cache = createCache([describeVpcs[0]], [describeNatGateways[0]], [], []);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is using managed NAT Gateway');
                done();
            });
        });

        it('should PASS if VPC has no NAT Gateway and no NAT instance', function (done) {
            const cache = createCache(
                [describeVpcs[1]],
                [describeNatGateways[0]],
                [describeRouteTables[0], describeRouteTables[2]],
                [describeInstances[1], describeInstances[2]]
            );
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is not using a NAT instance');
                done();
            });
        });

        it('should FAIL if VPC is using a NAT instance through a route table', function (done) {
            const cache = createCache(
                [describeVpcs[2]],
                [],
                [describeRouteTables[1]],
                [describeInstances[0]]
            );
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is using a NAT instance instead of a managed NAT Gateway');
                done();
            });
        });

        it('should only FAIL the VPC using a NAT instance when multiple VPCs are present', function (done) {
            const cache = createCache(
                [describeVpcs[0], describeVpcs[1], describeVpcs[2]],
                [describeNatGateways[0]],
                [describeRouteTables[0], describeRouteTables[1], describeRouteTables[2]],
                [describeInstances[0], describeInstances[1], describeInstances[2]]
            );
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(3);

                var gatewayResult = results.find(r => r.region === 'us-east-1' && r.message.includes('vpc-99de2fe4'));
                var noDeviceResult = results.find(r => r.message.includes('vpc-0b739af479bea9bff'));
                var natInstanceResult = results.find(r => r.message.includes('vpc-nat-instance-11111'));

                expect(gatewayResult.status).to.equal(0);
                expect(noDeviceResult.status).to.equal(0);
                expect(natInstanceResult.status).to.equal(2);
                done();
            });
        });

        it('should PASS and not crash when route tables are empty', function (done) {
            const cache = createCache([describeVpcs[1]], [], [], []);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS and not crash when route table references a terminated or nonexistent instance', function (done) {
            const cache = createCache(
                [describeVpcs[1]],
                [],
                [describeRouteTables[2]],
                [describeInstances[2]]
            );
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no VPCs found', function (done) {
            const cache = createCache([], [], [], []);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No AWS VPCs found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe VPCs', function (done) {
            const cache = createErrorCache();
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe route tables', function (done) {
            const cache = createRouteTablesErrorCache([describeVpcs[1]], []);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe instances', function (done) {
            const cache = createInstancesErrorCache([describeVpcs[1]], [], []);
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe VPCs response not found', function (done) {
            const cache = createNullCache();
            managedNatGateway.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
