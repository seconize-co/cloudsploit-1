var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Managed NAT Gateway In Use',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure AWS VPC Managed NAT (Network Address Translation) Gateway service is enabled for high availability (HA).',
    more_info: 'VPCs should use highly available Managed NAT Gateways in order to enable EC2 instances to connect to the internet or with other AWS components.',
    link: 'https://aws.amazon.com/blogs/aws/new-managed-nat-network-address-translation-gateway-for-aws/',
    recommended_action: 'Update VPCs to use Managed NAT Gateways instead of NAT instances',
    apis: ['EC2:describeVpcs', 'EC2:describeNatGateways', 'EC2:describeRouteTables', 'EC2:describeInstances', 'STS:getCallerIdentity'],
    realtime_triggers: ['ec2:CreateNatGateway', 'ec2:ReplaceRoute', 'ec2:CreateRoute', 'ec2:DeleteRoute', 'ec2:CreateVpc', 'ec2:DeleteNatGateway', 'ec2:DeleteVpc', 'ec2:RunInstances', 'ec2:TerminateInstances', 'ec2:ModifyInstanceAttribute'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        
        async.each(regions.ec2, function(region, rcb){
            var foundVpcIds = [];

            var describeVpcs = helpers.addSource(cache, source,
                ['ec2', 'describeVpcs', region]);

            if (!describeVpcs) return rcb();

            if (describeVpcs.err || !describeVpcs.data) {
                helpers.addResult(results, 3,
                    `Unable to query for VPCs: ${helpers.addError(describeVpcs)}`, region);
                return rcb();
            }

            if (!describeVpcs.data.length) {
                helpers.addResult(results, 0, 'No AWS VPCs found', region);
                return rcb();
            }

            var describeNatGateways = helpers.addSource(cache, source,
                ['ec2', 'describeNatGateways', region]);

            if (!describeNatGateways || describeNatGateways.err || !describeNatGateways.data) {
                helpers.addResult(results, 3,
                    `Unable to query for NAT Gateways: ${helpers.addError(describeNatGateways)}`, region);
                return rcb();
            }

            if (describeNatGateways.data.length) {
                describeNatGateways.data.forEach(function(nat){
                    if (nat.VpcId && !foundVpcIds.includes(nat.VpcId)) {
                        foundVpcIds.push(nat.VpcId);
                    }
                });
            }

            var describeRouteTables = helpers.addSource(cache, source,
                ['ec2', 'describeRouteTables', region]);

            if (!describeRouteTables || describeRouteTables.err || !describeRouteTables.data) {
                helpers.addResult(results, 3,
                    `Unable to query for route tables: ${helpers.addError(describeRouteTables)}`, region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            // An instance is only capable of acting as a NAT instance if it is alive
            // and has source/destination checking disabled (a requirement for NAT instances).
            var natCapableInstanceIds = [];
            describeInstances.data.forEach(function(reservation){
                if (!reservation.Instances || !reservation.Instances.length) return;

                reservation.Instances.forEach(function(instance){
                    if (!instance.InstanceId || instance.SourceDestCheck !== false) return;
                    if (instance.State && instance.State.Name &&
                        ['terminated', 'shutting-down'].includes(instance.State.Name)) return;

                    natCapableInstanceIds.push(instance.InstanceId);
                });
            });

            // A VPC is using a NAT instance when one of its route tables has a route
            // pointing to an EC2 instance that is actually configured as a NAT instance.
            var natInstanceVpcIds = [];
            describeRouteTables.data.forEach(function(routeTable){
                if (!routeTable.VpcId || !routeTable.Routes || !routeTable.Routes.length) return;
                if (natInstanceVpcIds.includes(routeTable.VpcId)) return;

                var usesNatInstance = routeTable.Routes.some(function(route){
                    return route.InstanceId && natCapableInstanceIds.includes(route.InstanceId);
                });

                if (usesNatInstance) natInstanceVpcIds.push(routeTable.VpcId);
            });

            describeVpcs.data.forEach(function(vpc){
                var resource = `arn:${awsOrGov}:vpc:${region}:${accountId}:/vpc/${vpc.VpcId}`;

                if (foundVpcIds.includes(vpc.VpcId)) {
                    helpers.addResult(results, 0,
                        `VPC "${vpc.VpcId}" is using managed NAT Gateway`,
                        region, resource);
                } else if (natInstanceVpcIds.includes(vpc.VpcId)) {
                    helpers.addResult(results, 2,
                        `VPC "${vpc.VpcId}" is using a NAT instance instead of a managed NAT Gateway`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `VPC "${vpc.VpcId}" is not using a NAT instance and does not require a managed NAT Gateway`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};