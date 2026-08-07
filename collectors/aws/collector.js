/*********************
 Collector - The collector will query AWS APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AWSConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["us-east-2", "eu-west-1"],
     "api_calls": ["EC2:describeInstances", "S3:listBuckets"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var AWS = require('aws-sdk');
var async = require('async');
var https = require('https');
var helpers = require(__dirname + '/../../helpers/aws');
var collectors = require(__dirname + '/../../collectors/aws');

// Override max sockets and enable keep-alive so repeated calls to the
// same region/service endpoint reuse the TCP connection instead of
// paying for a new handshake every time
var agent = new https.Agent({keepAlive: true, maxSockets: 150});
// Bound only the TCP connect phase, not the overall request timeout: a
// healthy connection to an AWS endpoint should establish well within this,
// so this only cuts short a genuinely hung/blackholed connection attempt
// (which would otherwise tie up one of the limited region-concurrency slots
// for a very long time) without risking cutting off any legitimately slow
// but successful call (e.g. large paginated responses, credential report
// generation), whose duration is unaffected by connectTimeout.
AWS.config.update({httpOptions: {agent: agent, connectTimeout: 5000}});

var globalServices = [
    'S3',
    'IAM',
    'CloudFront',
    'Route53',
    'Route53Domains',
    'WAFRegional'
];

var calls = {
    ACM: {
        listCertificates: {
            property: 'CertificateSummaryList',
            paginate: 'NextToken'
        }
    },
    APIGateway: {
        getRestApis: {
            property: 'items',
            paginate: 'NextToken'
        }
    },
    Athena: {
        listWorkGroups: {
            property: 'WorkGroups',
            paginate: 'NextToken',
            params: {
                MaxResults: 50
            }
        }
    },
    AutoScaling: {
        describeAutoScalingGroups: {
            property: 'AutoScalingGroups',
            paginate: 'NextToken',
            params: {
                MaxRecords: 100
            }
        },
        describeLaunchConfigurations: {
            property: 'LaunchConfigurations',
            paginate: 'NextToken',
            params: {
                MaxRecords: 100
            }
        }
    },
    CloudFormation: {
        listStacks: {
            property: 'StackSummaries',
            params: {
                'StackStatusFilter': [
                    'CREATE_IN_PROGRESS',
                    'CREATE_COMPLETE',
                    'ROLLBACK_IN_PROGRESS',
                    'ROLLBACK_FAILED',
                    'ROLLBACK_COMPLETE',
                    'DELETE_FAILED',
                    'UPDATE_IN_PROGRESS',
                    'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_COMPLETE',
                    'UPDATE_ROLLBACK_IN_PROGRESS',
                    'UPDATE_ROLLBACK_FAILED',
                    'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_ROLLBACK_COMPLETE',
                    'REVIEW_IN_PROGRESS',
                    'IMPORT_IN_PROGRESS',
                    'IMPORT_COMPLETE',
                    'IMPORT_ROLLBACK_IN_PROGRESS',
                    'IMPORT_ROLLBACK_FAILED',
                    'IMPORT_ROLLBACK_COMPLETE',
                ]
            }
        },
    },
    CloudFront: {
        // TODO: Pagination is using an older format
        listDistributions: {
            property: 'DistributionList',
            secondProperty: 'Items'
        }
    },
    CloudTrail: {
        describeTrails: {
            property: 'trailList'
        }
    },
    CloudWatchLogs: {
        describeLogGroups: {
            property: 'logGroups',
            paginate: 'nextToken',
            params: {
                limit: 50
            }
        },
        describeMetricFilters: {
            property: 'metricFilters',
            paginate: 'nextToken',
            params: {
                limit: 50 // The max available
            }
        }
    },
    CodeStar: {
        listProjects: {
            property: 'projects',
            paginate: 'nextToken'
        }
    },
    CodeBuild: {
        listProjects: {
            property: 'projects',
            paginate: 'nextToken'
        }
    },
    Comprehend: {
        listEntitiesDetectionJobs: {
            property: 'EntitiesDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listDocumentClassificationJobs: {
            property: 'DocumentClassificationJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listDominantLanguageDetectionJobs: {
            property: 'DominantLanguageDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listKeyPhrasesDetectionJobs: {
            property: 'KeyPhrasesDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listSentimentDetectionJobs: {
            property: 'SentimentDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        },
        listTopicsDetectionJobs: {
            property: 'TopicsDetectionJobPropertiesList',
            paginate: 'NextToken',
            params: {
                MaxResults: 100
            }
        }
    },
    ConfigService: {
        describeConfigurationRecorders: {
            property: 'ConfigurationRecorders'
        },
        describeConfigurationRecorderStatus: {
            property: 'ConfigurationRecordersStatus'
        }
    },
    DevOpsGuru: {
        listNotificationChannels: {
            property: 'Channels',
            paginate: 'NextToken'
        }
    },
    DirectConnect: {
        describeDirectConnectGateways: {
            property: 'directConnectGateways',
            paginate: 'nextToken'
        }
    },
    DirectoryService: {
        describeDirectories: {
            property: 'DirectoryDescriptions',
            paginate: 'NextToken'
        }
    },
    DLM: {
        getLifecyclePolicies: {
            property: 'Policies'
        }
    },
    DMS: {
        describeReplicationInstances: {
            property: 'ReplicationInstances',
            paginate: 'Marker'
        }
    },
    DynamoDB: {
        listTables: {
            property: 'TableNames',
            paginate: 'LastEvaluatedTableName',
            paginateReqProp: 'ExclusiveStartTableName'
        }
    },
    DAX: {
        describeClusters: {
            property: 'Clusters',
            paginate: 'NextToken'
        }
    },
    EC2: {
        describeAccountAttributes: {
            property: 'AccountAttributes'
        },
        describeSubnets: {
            property: 'Subnets',
            paginate: 'NextToken'
        },
        describeAddresses: {
            property: 'Addresses'
        },
        describeVolumes: {
            property: 'Volumes'
        },
        describeInstances: {
            property: 'Reservations',
            paginate: 'NextToken',
            params: {
                MaxResults: 1000,
                Filters: [
                    {
                        Name: 'instance-state-name',
                        Values: [
                            'pending',
                            'running',
                            'shutting-down',
                            'stopping',
                            'stopped'
                        ]
                    }
                ]
            }
        },
        describeSecurityGroups: {
            property: 'SecurityGroups'
        },
        describeVpcs: {
            property: 'Vpcs',
            paginate: 'NextToken'
        },
        describeFlowLogs: {
            // TODO: override bc flowlogs are not available in all regions?
            property: 'FlowLogs'
        },
        describeImages: {
            property: 'Images',
            params: {
                Owners: [
                    'self'
                ],
                Filters: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeInternetGateways: {
            property: 'InternetGateways'
        },
        describeEgressOnlyInternetGateways: {
            property: 'EgressOnlyInternetGateways'
        },
        describeNatGateways: {
            property: 'NatGateways',
            paginate: 'NextToken',
            params: {
                Filter: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeVpcPeeringConnections: {
            property: 'VpcPeeringConnections',
            paginate: 'NextToken',
            params: {
                Filters: [
                    {
                        Name: 'status-code',
                        Values: [
                            'pending-acceptance',
                            'provisioning',
                            'active'
                        ]
                    }
                ]
            }
        },
        describeVpnGateways: {
            property: 'VpnGateways',
            params: {
                Filters: [
                    {
                        Name: 'state',
                        Values: [
                            'available'
                        ]
                    }
                ]
            }
        },
        describeVpcEndpointServices: {
            property: 'ServiceDetails',
            paginate: 'NextToken'
        },
        describeVpcEndpoints: {
            property: 'VpcEndpoints',
            paginate: 'NextToken'
        },
        describeRouteTables: {
            property: 'RouteTables',
            paginate: 'NextToken'
        },
        describeTags: {
            property: 'Tags',
            paginate: 'NextToken',
        },
        describeNetworkInterfaces: {
            property: 'NetworkInterfaces',
            paginate: 'NextToken',
        },
        getEbsEncryptionByDefault: {
            property: 'EbsEncryptionByDefault'
        },
        getEbsDefaultKmsKeyId: {
            property: 'KmsKeyId'
        },
        describeVpnConnections: {
            property: 'VpnConnections',
            paginate: 'NextToken'
        },
        describeNetworkAcls: {
            property: 'NetworkAcls',
            paginate: 'NextToken',
        }

    },
    ECR: {
        describeRepositories: {
            property: 'repositories',
            paginate: 'nextToken',
            params: {
                maxResults: 1000
            }
        }
    },
    EFS: {
        describeFileSystems: {
            property: 'FileSystems',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    EKS: {
        listClusters: {
            property: 'clusters',
            paginate: 'nextToken'
        }
    },
    ECS: {
        listClusters: {
            property: 'clusterArns',
            paginate: 'nextToken'
        }
    },
    ElasticBeanstalk: {
        describeEnvironments: {
            property: 'Environments',
            paginate: 'NextToken'
        }
    },
    ElasticTranscoder: {
        // TODO: Pagination via NextPageToken and PageToken
        listPipelines: {
            property: 'Pipelines',
            paginate: 'NextPageToken',
            paginateReqProp: 'PageToken'
        }
    },
    ELB: {
        describeLoadBalancers: {
            property: 'LoadBalancerDescriptions',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    ELBv2: {
        describeLoadBalancers: {
            property: 'LoadBalancers',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        },
        describeTargetGroups: {
            property: 'TargetGroups',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        },
        describeTargetHealth: {
            property: 'TargetGroups',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    EMR: {
        listClusters: {
            property: 'Clusters',
            paginate: 'Marker',
            params: {
                ClusterStates: [
                    'RUNNING'
                ]
            }
        }
    },
    ES: {
        listDomainNames: {
            property: 'DomainNames'
        }
    },
    Glue: {
        getDataCatalogEncryptionSettings: {
            property: 'DataCatalogEncryptionSettings',
        },
        getSecurityConfigurations: {
            property: 'SecurityConfigurations',
            paginate: 'NextMarker'
        }
    },
    IAM: {
        listServerCertificates: {
            property: 'ServerCertificateMetadataList',
            paginate: 'Marker'
        },
        listGroups: {
            property: 'Groups',
            paginate: 'Marker'
        },
        listUsers: {
            property: 'Users',
            paginate: 'Marker'
        },
        listRoles: {
            property: 'Roles',
            paginate: 'Marker'
        },
        listPolicies: {
            property: 'Policies',
            paginate: 'Marker',
            params: {
                OnlyAttached: true
            }
        },
        listVirtualMFADevices: {
            property: 'VirtualMFADevices',
            paginate: 'Marker'
        },
        getAccountPasswordPolicy: {
            property: 'PasswordPolicy'
        },
        getAccountSummary: {
            property: 'SummaryMap'
        },
        generateCredentialReport: {
            override: true
        }
    },
    Kinesis: {
        listStreams: {
            property: 'StreamNames'
        }
    },
    Firehose: {
        listDeliveryStreams: {
            property: 'DeliveryStreamNames'
        }
    },
    GuardDuty: {
        listDetectors: {
            property: 'DetectorIds',
            paginate: 'NextToken',
        }
    },
    KMS: {
        listKeys: {
            property: 'Keys',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker',
            params: {
                Limit: 1000
            }
        },
        listAliases: {
            property: 'Aliases',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker',
            params: {
                Limit: 100
            }
        }
    },
    Lambda: {
        listFunctions: {
            property: 'Functions',
            paginate: 'NextMarker',
            paginateReqProp: 'Marker'
        }
    },
    MWAA: {
        listEnvironments: {
            property: 'Environments',
            paginate: 'NextToken'
        }
    },
    Organizations: {
        describeOrganization: {
            property: 'Organization',
        },
        listHandshakesForAccount: {
            property: 'Handshakes',
        },
        listAccounts: {
            property: 'Accounts',
            paginate: 'NextToken'
        },
    },
    RDS: {
        describeDBInstances: {
            property: 'DBInstances',
            paginate: 'Marker'
        },
        describeDBClusters: {
            property: 'DBClusters',
            paginate: 'Marker'
        },
        describeDBEngineVersions: {
            property: 'DBEngineVersions',
            paginate: 'Marker',
            default: true
        },
        describeDBSnapshots: {
            property: 'DBSnapshots',
            paginate: 'Marker'
        },
        describeDBParameterGroups: {
            property: 'DBParameterGroups',
            paginate: 'Marker'
        }
    },
    Redshift: {
        describeClusters: {
            property: 'Clusters',
            paginate: 'Marker'
        },
        describeClusterParameterGroups: {
            property: 'ParameterGroups',
            paginate: 'Marker'
        },
        describeReservedNodes: {
            property: 'ReservedNodes',
            paginate: 'Marker'
        }
    },
    ResourceGroupsTaggingAPI: {
        getTagKeys: {
            property: 'TagKeys',
            paginate: 'PaginationToken'
        }
    },
    Route53: {
        listHostedZones: {
            property: 'HostedZones',
            paginate: 'NextPageMarker',
            paginateReqProp: 'Marker'
        },
    },
    Route53Domains: {
        listDomains: {
            property: 'Domains',
            paginate: 'NextPageMarker',
            paginateReqProp: 'Marker'
        }
    },
    S3: {
        listBuckets: {
            property: 'Buckets'
        }
    },
    SageMaker: {
        listNotebookInstances: {
            property: 'NotebookInstances',
            paginate: 'NextToken'
        }
    },
    SecretsManager: {
        listSecrets: {
            property: 'SecretList',
            paginate: 'NextToken'
        }
    },
    ServiceQuotas: {
        listServiceQuotas: {
            property: 'Quotas',
            paginate: 'NextToken',
            params: {
                ServiceCode: 'ec2'
            },
        }
    },
    SES: {
        listIdentities: {
            property: 'Identities',
            paginate: 'NextToken',
            params: {
                IdentityType: 'Domain', // TODO: maybe don't filter these?
                MaxItems: 1000
            },
            rateLimit: 1000 // ms to rate limit between regions
        },
        describeActiveReceiptRuleSet: {
            property: 'Rules'
        }
    },
    Shield: {
        describeSubscription: {
            property: 'Subscription'
        },
        describeEmergencyContactSettings: {
            property: 'EmergencyContactList'
        },
        listProtections: {
            property: 'Protections'
        }
    },
    SNS: {
        listTopics: {
            property: 'Topics',
            paginate: 'NextToken'
        }
    },
    SQS: {
        listQueues: {
            property: 'QueueUrls'
        }
    },
    SSM: {
        describeInstanceInformation: {
            property: 'InstanceInformationList',
            params: {
                MaxResults: 50
            },
            paginate: 'NextToken'
        },
        describeParameters: {
            property: 'Parameters',
            params: {
                MaxResults: 50
            },
            paginate: 'NextToken'
        },
        listAssociations: {
            property: 'Associations',
            paginate: 'NextToken'
        }
    },
    STS: {
        getCallerIdentity: {
            property: 'Account'
        }
    },
    Support: {
        describeTrustedAdvisorChecks: {
            property: 'checks',
            params: { language: 'en' },
        },
    },
    Transfer: {
        listServers: {
            property: 'Servers',
            paginate: 'NextToken',
            params: {
                MaxResults: 1000
            }
        }
    },
    WAFRegional: {
        listWebACLs: {
            property: 'WebACLs',
            paginate: 'NextMarker'
        }
    },
    WAFV2: {
        listWebACLs: {
            property: 'WebACLs',
            paginate: 'NextMarker',
            params: {
                Scope: 'REGIONAL'
            }
        }
    },
    WorkSpaces: {
        describeWorkspaces: {
            property: 'Workspaces',
            paginate: 'NextToken'
        },
        describeWorkspaceDirectories:{
            property: 'Directories',
            paginate: 'NextToken'
        },
        describeIpGroups:{
            property: 'Result',
            paginate: 'NextToken'
        }
    },
    XRay: {
        getEncryptionConfig: {
            property: 'EncryptionConfig'
        }
    }
};

var postcalls = [
    {
        ACM: {
            describeCertificate: {
                reliesOnService: 'acm',
                reliesOnCall: 'listCertificates',
                filterKey: 'CertificateArn',
                filterValue: 'CertificateArn'
            }
        },
        APIGateway: {
            getStages: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                filterKey: 'restApiId',
                filterValue: 'id'
            }
        },
        Athena: {
            getWorkGroup: {
                reliesOnService: 'athena',
                reliesOnCall: 'listWorkGroups',
                filterKey: 'WorkGroup',
                filterValue: 'Name'
            }
        },
        AutoScaling: {
            describeNotificationConfigurations: {
                reliesOnService: 'autoscaling',
                reliesOnCall: 'describeAutoScalingGroups',
                override: true
            },
            describeLaunchConfigurations: {
                reliesOnService: 'autoscaling',
                reliesOnCall: 'describeAutoScalingGroups',
                override: true
            }
        },
        CloudFormation: {    
            describeStackEvents: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 100 // ms to rate limit between stacks
            },
            describeStacks: {
                reliesOnService: 'cloudformation',
                reliesOnCall: 'listStacks',
                filterKey: 'StackName',
                filterValue: 'StackName',
                rateLimit: 100 // ms to rate limit between stacks
            }
        },
        CloudFront: {
            getDistribution: {
                reliesOnService: 'cloudfront',
                reliesOnCall: 'listDistributions',
                override: true
            }
        },
        CloudTrail: {
            getTrailStatus: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                filterKey: 'Name',
                filterValue: 'TrailARN'
            },
            listTags: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                override: true
            },
            getEventSelectors: {
                reliesOnService: 'cloudtrail',
                reliesOnCall: 'describeTrails',
                filterKey: 'TrailName',
                filterValue: 'TrailARN'
            }
        },
        CodeStar: {
            describeProject: {
                reliesOnService: 'codestar',
                reliesOnCall: 'listProjects',
                filterKey: 'id',
                filterValue: 'projectId'
            }
        },
        CodeBuild: {
            batchGetProjects: {
                reliesOnService: 'codebuild',
                reliesOnCall: 'listProjects',
                override: true
            }
        },
        DynamoDB: {
            describeTable: {
                reliesOnService: 'dynamodb',
                reliesOnCall: 'listTables',
                override: true
            },
            describeContinuousBackups: {
                reliesOnService: 'dynamodb',
                reliesOnCall: 'listTables',
                override: true
            },
        },
        ES: {
            describeElasticsearchDomain: {
                reliesOnService: 'es',
                reliesOnCall: 'listDomainNames',
                filterKey: 'DomainName',
                filterValue: 'DomainName'
            }
        },
        S3: {
            getBucketLogging: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketVersioning: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketAcl: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketPolicy: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketEncryption: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketTagging: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketLocation: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getPublicAccessBlock: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketWebsite: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getObjectLockConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketLifecycleConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                deleteRegion: true,
                signatureVersion: 'v4',
                override: true
            },
            getBucketAccelerateConfiguration: {
                reliesOnService: 's3',
                reliesOnCall: 'listBuckets',
                filterKey: 'Bucket',
                filterValue: 'Name'
            },
        },
        EC2: {
            describeSubnets: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeVpcs',
                override: true
            },
            describeSnapshots: {
                // This call must be overridden because the
                // default call retrieves every snapshot
                // available, including public ones. Moved here (relying on
                // STS:getCallerIdentity, already collected once in the main
                // calls phase) instead of the main calls object so it no
                // longer needs its own fresh STS call per region.
                //
                // Intentionally no "reliesOnCall": STS only ever runs in a
                // single region (regions.sts), while EC2 runs in all of
                // them, so the framework's per-region reliesOnCall guard
                // (which indexes the dependency by the *current* region)
                // would incorrectly skip every EC2 region except the one
                // matching STS's region. The account-ID lookup is instead
                // done defensively inside the collector itself.
                reliesOnService: 'sts',
                override: true
            },
            describeSnapshotAttribute: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeSnapshots',
                override: true
            },
            describeVpcEndpointServicePermissions: {
                reliesOnService: 'ec2',
                reliesOnCall: 'describeVpcEndpointServices',
                filterKey: 'ServiceId',
                filterValue: 'ServiceId'
            }
        },
        ECR: {
            getRepositoryPolicy: {
                reliesOnService: 'ecr',
                reliesOnCall: 'describeRepositories',
                filterKey: 'repositoryName',
                filterValue: 'repositoryName'
            }
        },
        EKS: {
            describeCluster: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            },
            listNodegroups: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        ECS: {
            describeCluster: {
                reliesOnService: 'ecs',
                reliesOnCall: 'listClusters',
                override: true
            },
            listContainerInstances: {
                reliesOnService: 'ecs',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        ElasticBeanstalk: {
            describeConfigurationSettings: {
                reliesOnService: 'elasticbeanstalk',
                reliesOnCall: 'describeEnvironments',
                override: true
            }
        },
        ELB: {
            describeLoadBalancerPolicies: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeLoadBalancerAttributes: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTags: {
                reliesOnService: 'elb',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            }
        },
        ELBv2: {
            describeTargetHealth: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeTargetGroups',
                filterKey: 'TargetGroupArn',
                filterValue: 'TargetGroupArn'
            },
            describeLoadBalancerAttributes: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeListeners: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTargetGroups: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeLoadBalancers',
                override: true
            },
            describeTargetGroupAttributes: {
                reliesOnService: 'elbv2',
                reliesOnCall: 'describeTargetGroups',
                filterKey: 'TargetGroupArn',
                filterValue: 'TargetGroupArn'
            }
        },
        EMR: {
            describeCluster: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                filterKey: 'ClusterId',
                filterValue: 'Id'
            }
        },
        DLM: {
            getLifecyclePolicy: {
                reliesOnService: 'dlm',
                reliesOnCall: 'getLifecyclePolicies',
                filterKey: 'PolicyId',
                filterValue: 'PolicyId'
            }
        },
        IAM: {
            getGroup: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listAttachedUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listAttachedGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listAttachedRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            },
            listUserPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listGroupPolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                filterKey: 'GroupName',
                filterValue: 'GroupName'
            },
            listRolePolicies: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            },
            listSSHPublicKeys: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listMFADevices: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName'
            },
            listGroupsForUser: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                filterKey: 'UserName',
                filterValue: 'UserName',
                rateLimit: 100
            },
            // Moved up from the (formerly) second postcalls phase: these only
            // depend on main-calls data (listPolicies/listRoles), not on
            // anything collected elsewhere in this phase, so they no longer
            // need to wait for the entire phase above to finish first.
            getPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listPolicies',
                filterKey: 'PolicyArn',
                filterValue: 'Arn'
            },
            getRole: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                filterKey: 'RoleName',
                filterValue: 'RoleName'
            }
        },
        Kinesis: {
            describeStream: {
                reliesOnService: 'kinesis',
                reliesOnCall: 'listStreams',
                override: true
            }
        },
        Firehose: {
            describeDeliveryStream: {
                reliesOnService: 'firehose',
                reliesOnCall: 'listDeliveryStreams',
                override: true
            }
        },
        KMS: {
            describeKey: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            },
            getKeyRotationStatus: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            },
            getKeyPolicy: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                override: true
            },
            listResourceTags: {
                reliesOnService: 'kms',
                reliesOnCall: 'listKeys',
                filterKey: 'KeyId',
                filterValue: 'KeyId'
            }
        },
        Lambda: {
            getPolicy: {
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'FunctionName',
                filterValue: 'FunctionName',
                rateLimit: 100, // it's not documented but experimentially 10/second works.
            },
            listTags: {
                reliesOnService: 'lambda',
                reliesOnCall: 'listFunctions',
                filterKey: 'Resource',
                filterValue: 'FunctionArn'
            }
        },
        MWAA: {
            getEnvironment: {
                reliesOnService: 'mwaa',
                reliesOnCall: 'listEnvironments',
                override: true
            }
        },
        RDS: {
            describeDBParameters: {
                reliesOnService: 'rds',
                reliesOnCall: 'describeDBParameterGroups',
                filterKey: 'DBParameterGroupName',
                filterValue: 'DBParameterGroupName'
            }
        },
        Route53: {
            listResourceRecordSets: {
                reliesOnService: 'route53',
                reliesOnCall: 'listHostedZones',
                filterKey: 'HostedZoneId',
                filterValue: 'Id'
            },
        },
        S3Control: {
            getPublicAccessBlock: {
                reliesOnService: 'sts',
                reliesOnCall: 'getCallerIdentity',
                override: true
            }
        },
        Redshift: {
            describeClusterParameters: {
                reliesOnService: 'redshift',
                reliesOnCall: 'describeClusterParameterGroups',
                filterKey: 'ParameterGroupName',
                filterValue: 'ParameterGroupName'
            }
        },
        SageMaker: {
            describeNotebookInstance: {
                reliesOnService: 'sagemaker',
                reliesOnCall: 'listNotebookInstances',
                filterKey: 'NotebookInstanceName',
                filterValue: 'NotebookInstanceName'
            }
        },
        SecretsManager: {
            describeSecret: {
                reliesOnService: 'secretsmanager',
                reliesOnCall: 'listSecrets',
                filterKey: 'SecretId',
                filterValue: 'ARN',
            }
        },
        SES: {
            getIdentityDkimAttributes: {
                reliesOnService: 'ses',
                reliesOnCall: 'listIdentities',
                override: true,
                rateLimit: 1000
            }
        },
        SNS: {
            getTopicAttributes: {
                reliesOnService: 'sns',
                reliesOnCall: 'listTopics',
                filterKey: 'TopicArn',
                filterValue: 'TopicArn'
            }
        },
        SQS: {
            getQueueAttributes: {
                reliesOnService: 'sqs',
                reliesOnCall: 'listQueues',
                override: true
            }
        },
        Support: {
            describeTrustedAdvisorCheckResult: {
                reliesOnService: 'support',
                reliesOnCall: 'describeTrustedAdvisorChecks',
                filterKey: 'checkId',
                filterValue: 'id'
            },
        },
        WAFRegional: {
            listResourcesForWebACL: {
                reliesOnService: 'wafregional',
                reliesOnCall: 'listWebACLs',
                filterKey: 'WebACLId',
                filterValue: 'WebACLId',
                checkMultiple: ['APPLICATION_LOAD_BALANCER', 'API_GATEWAY'],
                checkMultipleKey: 'ResourceType'
            }
        },
        WAFV2: {
            listResourcesForWebACL: {
                reliesOnService: 'wafv2',
                reliesOnCall: 'listWebACLs',
                filterKey: 'WebACLArn',
                filterValue: 'ARN',
                checkMultiple: ['APPLICATION_LOAD_BALANCER', 'API_GATEWAY'],
                checkMultipleKey: 'ResourceType'
            }
        },
        GuardDuty: {
            getDetector: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
            getMasterAccount: {
                reliesOnService: 'guardduty',
                reliesOnCall: 'listDetectors',
                override: true,
            },
        },
    },
    {
        APIGateway: {
            getClientCertificate: {
                reliesOnService: 'apigateway',
                reliesOnCall: 'getRestApis',
                override: true
            }
        },
        EMR: {
            describeSecurityConfiguration: {
                reliesOnService: 'emr',
                reliesOnCall: 'listClusters',
                override: true
            }
        },
        IAM: {
            // getPolicyVersion only depends on IAM.getPolicy, which now runs
            // in the phase above - safe to run in this same phase rather
            // than waiting for an entire extra serial phase. Listed first so
            // it's scheduled as soon as this phase starts, rather than
            // behind getUserPolicy/getGroupPolicy/getRolePolicy (which it
            // does not depend on).
            getPolicyVersion: {
                reliesOnService: 'iam',
                reliesOnCall: 'listPolicies',
                override: true
            },
            getUserPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listUsers',
                override: true
            },
            getGroupPolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listGroups',
                override: true
            },
            getRolePolicy: {
                reliesOnService: 'iam',
                reliesOnCall: 'listRoles',
                override: true
            }
        },
        EKS:{
            describeNodegroups: {
                reliesOnService: 'eks',
                reliesOnCall: 'listClusters',
                override: true
            }
        }
    }
];

// Loop through all of the top-level collectors for each service
var collect = function(AWSConfig, settings, callback) {
    // Used to gather info only
    if (settings.gather) {
        return callback(null, calls, postcalls);
    }

    // Configure an opt-in debug logger
    var AWSXRay;
    var debugMode = settings.debug_mode;
    if (debugMode) AWSXRay = require('aws-xray-sdk');
    
    AWSConfig.maxRetries = 8;
    AWSConfig.retryDelayOptions = {base: 100};

    var regions = helpers.regions(settings);

    var collection = {};

    // Profiling: how long each service:call spent waiting on AWS, across all
    // of its regions. Printed as a "slowest 15" summary once collection is done.
    var apiCallTimings = [];

    async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
        var serviceLower = service.toLowerCase();
        if (!collection[serviceLower]) collection[serviceLower] = {};

        // Loop through each of the service's functions
        async.eachOfLimit(call, 15, function(callObj, callKey, callCb) {
            var callTimingStart = Date.now();
            var timedCallCb = function() { // eslint-disable-line no-inner-declarations
                apiCallTimings.push({name: service + ':' + callKey, ms: Date.now() - callTimingStart});
                callCb();
            };

            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return timedCallCb();
            if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

            var callRegions;

            if (callObj.default) {
                callRegions = regions.default;
            }  else {
                callRegions = regions[serviceLower];
            }

            async.eachLimit(callRegions, helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                if (settings.skip_regions &&
                    settings.skip_regions.indexOf(region) > -1 &&
                    globalServices.indexOf(service) === -1) return regionCb();
                // --region: limit execution to the selected regions only.
                // Global services (S3, IAM, etc.) are exempt, same as skip_regions above.
                if (settings.region && settings.region.length &&
                    settings.region.indexOf(region) === -1 &&
                    globalServices.indexOf(service) === -1) return regionCb();
                if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                // Shallow clone: only the top-level "region" key is ever written
                // onto this copy, so a full JSON deep clone isn't needed here
                var LocalAWSConfig = Object.assign({}, AWSConfig);
                LocalAWSConfig.region = region;

                if (callObj.override) {
                    collectors[serviceLower][callKey](LocalAWSConfig, collection, function() {
                        if (callObj.rateLimit) {
                            setTimeout(function() {
                                regionCb();
                            }, callObj.rateLimit);
                        } else {
                            regionCb();
                        }
                    });
                } else {
                    var executor;
                    try {
                        executor = debugMode ? (AWSXRay.captureAWSClient(new AWS[service](LocalAWSConfig))) : new AWS[service](LocalAWSConfig);
                    } catch (e) {
                        // Service name doesn't map to a real SDK class (e.g. a retired
                        // API on the current SDK version) - skip this call instead of
                        // crashing the whole scan
                        collection[serviceLower][callKey][region].err = e;
                        return regionCb();
                    }
                    var paginating = false;
                    var executorCb = function(err, data) {
                        if (err) collection[serviceLower][callKey][region].err = err;

                        if (!data) return regionCb();
                        if (callObj.property && !data[callObj.property]) return regionCb();
                        if (callObj.secondProperty && !data[callObj.secondProperty]) return regionCb();

                        var dataToAdd = callObj.secondProperty ? data[callObj.property][callObj.secondProperty] : data[callObj.property];

                        if (paginating) {
                            collection[serviceLower][callKey][region].data = collection[serviceLower][callKey][region].data.concat(dataToAdd);
                        } else {
                            collection[serviceLower][callKey][region].data = dataToAdd;
                        }

                        // If a "paginate" property is set, e.g. NextToken
                        var nextToken = callObj.paginate;
                        if (settings.paginate && nextToken && data[nextToken]) {
                            paginating = true;
                            var paginateProp = callObj.paginateReqProp ? callObj.paginateReqProp : nextToken;
                            return execute([paginateProp, data[nextToken]]);
                        }

                        if (callObj.rateLimit) {
                            setTimeout(function() {
                                regionCb();
                            }, callObj.rateLimit);
                        } else {
                            regionCb();
                        }
                    };

                    function execute(nextTokens) { // eslint-disable-line no-inner-declarations
                        // Each region needs its own local copy of callObj.params
                        // so that the injection of the NextToken doesn't break other calls
                        var localParams = Object.assign({}, callObj.params || {});
                        if (nextTokens) localParams[nextTokens[0]] = nextTokens[1];

                        if (callObj.params || nextTokens) {
                            executor[callKey](localParams, executorCb);
                        } else {
                            executor[callKey](executorCb);
                        }
                    }

                    execute();
                }
            }, function() {
                timedCallCb();
            });
        }, function() {
            serviceCb();
        });
    }, function() {
        // Now loop through the follow up calls
        async.eachSeries(postcalls, function(postcallObj, postcallCb) {
            async.eachOfLimit(postcallObj, 10, function(serviceObj, service, serviceCb) {
                var serviceLower = service.toLowerCase();
                if (!collection[serviceLower]) collection[serviceLower] = {};

                async.eachOfLimit(serviceObj, 1, function(callObj, callKey, callCb) {
                    if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                    // Entries with no override and no reliesOnService carry only
                    // integration metadata - there's no real call to make, so skip
                    // immediately instead of falling through to an attempted call
                    if (!callObj.override && !callObj.reliesOnService) return callCb();
                    if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

                    async.eachLimit(regions[serviceLower], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                        if (settings.skip_regions &&
                            settings.skip_regions.indexOf(region) > -1 &&
                            globalServices.indexOf(service) === -1) return regionCb();
                        // --region: limit execution to the selected regions only.
                        // Global services (S3, IAM, etc.) are exempt, same as skip_regions above.
                        if (settings.region && settings.region.length &&
                            settings.region.indexOf(region) === -1 &&
                            globalServices.indexOf(service) === -1) return regionCb();
                        if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                        // Ensure pre-requisites are met
                        if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return regionCb();

                        if (callObj.reliesOnCall &&
                            (!collection[callObj.reliesOnService] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data.length))
                            return regionCb();

                        // Shallow clone: only "region"/"signatureVersion" top-level keys
                        // are ever written onto this copy
                        var LocalAWSConfig = Object.assign({}, AWSConfig);
                        if (callObj.deleteRegion) {
                            //delete LocalAWSConfig.region;
                            LocalAWSConfig.region = settings.govcloud ? 'us-gov-west-1' : settings.china ? 'cn-north-1' : 'us-east-1';
                        } else {
                            LocalAWSConfig.region = region;
                        }
                        if (callObj.signatureVersion) LocalAWSConfig.signatureVersion = callObj.signatureVersion;

                        if (callObj.override) {
                            collectors[serviceLower][callKey](LocalAWSConfig, collection, function() {
                                if (callObj.rateLimit) {
                                    setTimeout(function() {
                                        regionCb();
                                    }, callObj.rateLimit);
                                } else {
                                    regionCb();
                                }
                            });
                        } else {
                            var executor;
                            try {
                                executor = debugMode ? (AWSXRay.captureAWSClient(new AWS[service](LocalAWSConfig))) : new AWS[service](LocalAWSConfig);
                            } catch (e) {
                                // Service name doesn't map to a real SDK class - skip
                                // this call instead of crashing the whole scan
                                collection[serviceLower][callKey][LocalAWSConfig.region].err = e;
                                return regionCb();
                            }

                            if (!collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data) {
                                return regionCb();
                            }

                            async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data, 10, function(dep, depCb) {
                                if (callObj.checkMultiple) {
                                    async.each(callObj.checkMultiple, function(thisCheck, tcCb){
                                        collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]] = {};

                                        var filter = {};
                                        filter[callObj.filterKey] = dep[callObj.filterValue];
                                        filter[callObj.checkMultipleKey] = thisCheck;

                                        executor[callKey](filter, function(err, data) {
                                            if (err) {
                                                collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].err = err;
                                            }
                                            if (data) {
                                                if (!collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].data) {
                                                    collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].data = data;
                                                }
                                            }
                                            tcCb();
                                        });
                                    }, function() {
                                        depCb();
                                    });
                                } else {
                                    collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]] = {};

                                    var filter = {};
                                    filter[callObj.filterKey] = dep[callObj.filterValue];
                                    executor[callKey](filter, function(err, data) {
                                        if (err) {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].err = err;
                                        } else {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].data = data;   
                                        }
                                        if (callObj.rateLimit) {
                                            setTimeout(function() {
                                                depCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            depCb();
                                        }
                                    });
                                }
                            }, function() {
                                if (callObj.rateLimit) {
                                    setTimeout(function() {
                                        regionCb();
                                    }, callObj.rateLimit);
                                } else {
                                    regionCb();
                                }
                            });
                        }
                    }, function() {
                        callCb();
                    });
                }, function() {
                    serviceCb();
                });
            }, function() {
                postcallCb();
            });
        }, function() {
            if (apiCallTimings.length) {
                var slowest = apiCallTimings.slice().sort(function(a, b) { return b.ms - a.ms; }).slice(0, 15);
                console.log('INFO: Slowest 15 API calls:');
                slowest.forEach(function(t) {
                    console.log(`  ${t.name}: ${t.ms}ms`);
                });
            }
            callback(null, collection);
        });
    });
};

module.exports = collect;
