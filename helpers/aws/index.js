var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var api = require('./api.js');
var api_multipart = require('./api_multipart.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');
var govRegionsFedRampEast1  = require('./regions_gov_fedramp_east_1.js');
var govRegionsFedRampWest1  = require('./regions_gov_fedramp_west_1.js');
var chinaRegions = require('./regions_china.js');

// Services that operate on a single, account-wide API endpoint rather than
// per-region ones. Derived from api.js's globalServices (the same list the
// collector itself uses to exempt regions from skip_regions/--region
// filtering) so this can never drift out of sync with it - if it did,
// --region would filter a global service's region list down to nothing here
// while the collector still expects to find its (unfiltered) data.
var GLOBAL_SERVICE_KEYS = api.globalServices.map(function(s) { return s.toLowerCase(); });

// Keys in the regions.js maps that aren't a specific AWS service's region
// list (an overall region catalog, a single-region default, and the set of
// opt-in-only regions) - never filtered by --region.
var NON_SERVICE_KEYS = ['all', 'default', 'optin'];

// Account-level services collected only in the default region (us-east-1), never filtered by --region:
// - sts: plugins read the account id from sts:getCallerIdentity there to build resource ARNs. Filtering
//   it would leave "null" as the account id whenever the default region is not selected, giving the
//   same resources different ARNs depending on the selected regions.
// - shield, organizations: account-wide settings reported as 'global'. Filtering them would drop those
//   checks from every scan that does not select us-east-1.
var ALWAYS_COLLECTED_KEYS = ['sts', 'shield', 'organizations'];

// Collector service names of ALWAYS_COLLECTED_KEYS (helpers/aws/api.js).
var ALWAYS_COLLECTED_SERVICES = ['STS', 'Shield', 'Organizations'];

var regions = function(settings) {
    var base;
    if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-east-1') base = govRegionsFedRampEast1;
    else if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-west-1') base = govRegionsFedRampWest1;
    else if (settings.govcloud) base = govRegions;
    else if (settings.china) base = chinaRegions;
    else base = regRegions;

    // settings.region is only a parsed array once index.js has validated it;
    // during that validation call it's still the raw comma-separated string,
    // and Array.isArray correctly skips filtering so validation always sees
    // the full, unfiltered region catalog.
    if (!Array.isArray(settings.region) || !settings.region.length) return base;

    var filtered = {};
    Object.keys(base).forEach(function(key) {
        if (NON_SERVICE_KEYS.indexOf(key) !== -1 || GLOBAL_SERVICE_KEYS.indexOf(key) !== -1 || ALWAYS_COLLECTED_KEYS.indexOf(key) !== -1) {
            filtered[key] = base[key];
        } else {
            filtered[key] = base[key].filter(function(r) { return settings.region.indexOf(r) !== -1; });
        }
    });
    return filtered;
};

var helpers = {
    regions: regions,
    alwaysCollectedServices: ALWAYS_COLLECTED_SERVICES,
    MAX_REGIONS_AT_A_TIME: 20,
    CLOUDSPLOIT_EVENTS_BUCKET: 'cloudsploit-engine-trails',
    CLOUDSPLOIT_EVENTS_SNS: 'aqua-cspm-sns-',
    ENCRYPTION_LEVELS: ['none', 'sse', 'awskms', 'awscmk', 'externalcmk', 'cloudhsm'],
    IAM_CONDITION_OPERATORS: {
        string: {
            Allow: ['StringEquals', 'StringEqualsIgnoreCase', 'StringLike'],
            Deny: ['StringNotEquals', 'StringNotEqualsIgnoreCase', 'StringNotLike']
        },
        arn: {
            Allow: ['ArnEquals', 'ArnLike'],
            Deny: ['ArnNotEquals', 'ArnNotLike']
        },
        ipaddress: {
            Allow: 'IpAddress',
            Deny: 'NotIpAddress'
        }
    },
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];
for (var a in api) helpers[a] = api[a];
for (var am in api_multipart) helpers[am] = api_multipart[am];

module.exports = helpers;