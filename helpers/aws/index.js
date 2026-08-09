var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');
var chinaRegions = require('./regions_china.js');

// Services that operate on a single, account-wide API endpoint rather than
// per-region ones. Mirrors the globalServices list in
// collectors/aws/collector.js: the collector always gathers their data in
// this one region regardless of --region, so their region list here must
// never be filtered down or plugins would stop finding data the collector
// did fetch.
var GLOBAL_SERVICE_KEYS = ['s3', 'iam', 'cloudfront', 'route53', 'route53domains'];

// Keys in the regions.js maps that aren't a specific AWS service's region
// list (an overall region catalog, a single-region default, and the set of
// opt-in-only regions) - never filtered by --region.
var NON_SERVICE_KEYS = ['all', 'default', 'optin'];

var regions = function(settings) {
    var base = settings.govcloud ? govRegions : settings.china ? chinaRegions : regRegions;

    // settings.region is only a parsed array once index.js has validated it;
    // during that validation call it's still the raw comma-separated string,
    // and Array.isArray correctly skips filtering so validation always sees
    // the full, unfiltered region catalog.
    if (!Array.isArray(settings.region) || !settings.region.length) return base;

    var filtered = {};
    Object.keys(base).forEach(function(key) {
        if (NON_SERVICE_KEYS.indexOf(key) !== -1 || GLOBAL_SERVICE_KEYS.indexOf(key) !== -1) {
            filtered[key] = base[key];
        } else {
            filtered[key] = base[key].filter(function(r) { return settings.region.indexOf(r) !== -1; });
        }
    });
    return filtered;
};

var helpers = {
    regions: regions,
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

module.exports = helpers;
