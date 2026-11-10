<?php

declare(strict_types=1);

require_once __DIR__ . '/../autoload.php';

use IpScope\Sdk\CacheOptions;
use IpScope\Sdk\FeedbackSubmissionInput;
use IpScope\Sdk\HttpTransport;
use IpScope\Sdk\IpLookupResponse;
use IpScope\Sdk\IpScopeApiException;
use IpScope\Sdk\IpScopeClient;
use IpScope\Sdk\IpScopeMemoryLimitException;
use IpScope\Sdk\IpScopeSecurity;
use IpScope\Sdk\IpScopeValidationException;
use IpScope\Sdk\IpScopeValidator;
use IpScope\Sdk\LruTtlCache;
use IpScope\Sdk\RetryOptions;

$passed = 0;
$failed = 0;

// Example key in the real token format: <uuid>:<43-char base64url secret>. Not a real key.
const TEST_API_KEY = '3f6b2a91-7c4d-4e8a-9b1f-2d5c8e0a4b7c:Zm9vYmFyYmF6cXV4Y29yZ2VncmF1bHRnYXJwbHl3YWw';

function assertTrue(bool $condition, string $message): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
    } else {
        $failed++;
        fwrite(STDERR, "FAIL: {$message}\n");
    }
}

function assertSame(mixed $expected, mixed $actual, string $message): void
{
    assertTrue($expected === $actual, sprintf('%s (expected %s, got %s)', $message, var_export($expected, true), var_export($actual, true)));
}

/**
 * Raw JSON of a captured or contract-built API response in tests/fixtures.
 */
function fixtureJson(string $name): string
{
    $body = file_get_contents(__DIR__ . '/fixtures/' . $name . '.json');
    if ($body === false) {
        throw new RuntimeException('Missing fixture ' . $name);
    }
    return $body;
}

/**
 * @return array<string, mixed>
 */
function fixture(string $name): array
{
    return json_decode(fixtureJson($name), true, 32, JSON_THROW_ON_ERROR);
}

/**
 * The live 1.1.1.1 lookup body with the address swapped, for tests that need many distinct IPs.
 *
 * @return array<string, mixed>
 */
function lookupPayloadFor(string $ip): array
{
    $payload = fixture(str_contains($ip, ':') ? 'lookup_2606_4700_4700__1111' : 'lookup_1.1.1.1');
    $payload['ip'] = $ip;
    return $payload;
}

// ---------------------------------------------------------------------------
// 1. Runtime advisory & memory-safety guard
// ---------------------------------------------------------------------------
assertSame(false, IpScopeSecurity::isPhpVersionPatched(80130), 'PHP 8.1 is unpatched');
assertSame(false, IpScopeSecurity::isPhpVersionPatched(80234), 'PHP 8.2.34 is unpatched');
assertSame(true, IpScopeSecurity::isPhpVersionPatched(80235), 'PHP 8.2.35 is patched');
assertSame(false, IpScopeSecurity::isPhpVersionPatched(80335), 'PHP 8.3.35 is unpatched');
assertSame(true, IpScopeSecurity::isPhpVersionPatched(80336), 'PHP 8.3.36 is patched');
assertSame(false, IpScopeSecurity::isPhpVersionPatched(80426), 'PHP 8.4.26 is unpatched');
assertSame(true, IpScopeSecurity::isPhpVersionPatched(80427), 'PHP 8.4.27 is patched');
assertSame(false, IpScopeSecurity::isPhpVersionPatched(80510), 'PHP 8.5.10 is unpatched');
assertSame(true, IpScopeSecurity::isPhpVersionPatched(80512), 'PHP 8.5.12 is patched');

$advisoryUnpatched = IpScopeSecurity::getRuntimeAdvisoryStatus(80510, '8.5.10');
assertSame(false, $advisoryUnpatched['patched'], 'Advisory status reports unpatched for 8.5.10');
assertSame(['CVE-2026-109618', 'CVE-2026-109619'], $advisoryUnpatched['advisories'], 'Advisory lists both CVEs');

assertSame(-1, IpScopeSecurity::getPhpMemoryLimitBytes('-1'), 'Unlimited memory_limit returns -1');
assertSame(128 * 1024 * 1024, IpScopeSecurity::getPhpMemoryLimitBytes('128M'), '128M parsed in bytes');
assertSame(2 * 1024 * 1024 * 1024, IpScopeSecurity::getPhpMemoryLimitBytes('2G'), '2G parsed in bytes');

$oomCaught = false;
try {
    IpScopeSecurity::assertMemoryHeadroom(
        additionalBytes: 1024 * 1024,
        minFreeHeadroomBytes: 8 * 1024 * 1024,
        overrideLimitBytes: 64 * 1024 * 1024,
        overrideCurrentUsageBytes: 60 * 1024 * 1024
    );
} catch (IpScopeMemoryLimitException $e) {
    $oomCaught = true;
    assertSame('IPSCOPE_MEMORY_LIMIT_GUARD', $e->errorCode, 'Pre-OOM guard sets IPSCOPE_MEMORY_LIMIT_GUARD code');
}
assertTrue($oomCaught, 'Pre-OOM guard throws IpScopeMemoryLimitException');

// ---------------------------------------------------------------------------
// 2. Zero-DNS validator
// ---------------------------------------------------------------------------
assertSame('8.8.8.8', IpScopeValidator::validateIpAddress('  8.8.8.8  '), 'IPv4 canonicalized');
assertSame(
    '2001:db8::1',
    IpScopeValidator::validateIpAddress('2001:0db8:0000:0000:0000:0000:0000:0001%eth0'),
    'IPv6 compressed & zone stripped'
);

$invalidIpCaught = false;
try {
    IpScopeValidator::validateIpAddress('dns.google.com');
} catch (IpScopeValidationException) {
    $invalidIpCaught = true;
}
assertTrue($invalidIpCaught, 'Hostnames rejected without DNS lookup');

$cidr4 = IpScopeValidator::validateCidrPrefix('8.8.8.42/24');
assertSame('8.8.8.0/24', $cidr4['canonicalCidr'], 'IPv4 CIDR host bits masked');

$cidr6 = IpScopeValidator::validateCidrPrefix('2001:4860:4860::8888/32');
assertSame('2001:4860::/32', $cidr6['canonicalCidr'], 'IPv6 CIDR host bits masked');

$deduped = IpScopeValidator::validateAndDeduplicateBatchIps(['8.8.8.8', '1.1.1.1', '8.8.8.8']);
assertSame(['8.8.8.8', '1.1.1.1'], $deduped, 'Batch deduplicates while preserving order');

// ---------------------------------------------------------------------------
// 3. Models parse real API JSON (captured from api.ipscope.io)
// ---------------------------------------------------------------------------
$v4 = IpLookupResponse::fromArray(fixture('lookup_1.1.1.1'));
assertSame('1.1.1.1', $v4->ip, 'ip parsed');
assertSame(4, $v4->ipVersion, 'ip_version parsed');
assertSame('1.1.1.0/24', $v4->matchedNetwork, 'matched_network parsed');
assertSame('2026-11-10', $v4->datasetVersion, 'dataset_version parsed');
assertSame('2026-11-04T21:07:15.284Z', $v4->updatedAt, 'updated_at parsed');
assertSame('AU', $v4->geo->countryCode, 'geo.country_code parsed');
assertSame('New South Wales', $v4->geo->subdivision, 'geo.subdivision parsed');
assertSame('Sydney', $v4->geo->city, 'geo.city parsed');
assertSame(null, $v4->geo->postalCode, 'absent geo.postal_code is null');
assertSame(-33.8688, $v4->geo->latitude, 'geo.latitude parsed');
assertSame(151.209, $v4->geo->longitude, 'geo.longitude parsed');
assertSame('Australia/Sydney', $v4->geo->timezone, 'geo.timezone parsed');
assertSame('declared', $v4->geo->locationType, 'geo.location_type parsed');
assertSame(0.85, $v4->geo->confidence, 'geo.confidence parsed');
assertSame(300.0, $v4->geo->accuracyRadiusKm, 'geo.accuracy_radius_km parsed');
assertSame('AU', $v4->geo->declaredCountryCode, 'geo.declared_country_code parsed');
assertSame(null, $v4->geo->physicalCountryCode, 'null geo.physical_country_code stays null');
assertSame(null, $v4->geo->isVirtualLocation, 'null geo.is_virtual_location stays null (not false)');
assertSame(13335, $v4->network->asn, 'network.asn parsed');
assertSame('CLOUDFLARENET - Cloudflare, Inc.', $v4->network->organization, 'network.organization parsed');
assertSame(false, $v4->security->isVpn, 'security.is_vpn parsed');
assertSame(true, $v4->security->isHosting, 'security.is_hosting parsed');
assertSame(false, $v4->security->isTorExit, 'security.is_tor_exit parsed');
assertSame(false, $v4->security->isProxy, 'security.is_proxy parsed');
assertSame(false, $v4->security->isRelay, 'security.is_relay parsed');
assertSame('none', $v4->security->anonymizerType, 'security.anonymizer_type parsed');
assertSame(0.85, $v4->security->confidence, 'security.confidence parsed');
assertSame(4, count($v4->security->reasonCodes), 'security.reason_codes parsed');
assertSame('BGP_ORIGIN_ASN_MATCHED', $v4->security->reasonCodes[0], 'first reason code parsed');
assertSame('hosting', $v4->connection?->connectionType, 'connection.connection_type parsed');
assertSame(false, $v4->connection?->isResidential, 'connection.is_residential parsed');
assertSame(true, $v4->connection?->isHosting, 'connection.is_hosting parsed');
assertSame(0.14, $v4->securityExtensions?->abuseVelocityScore, 'pre-0-100 fractional abuse_velocity_score passed through');
assertSame(false, $v4->securityExtensions?->isKnownScanner, 'security_extensions.is_known_scanner parsed');
assertSame(0.0, $v4->securityExtensions?->observationRecencyHours, 'security_extensions.observation_recency_hours parsed');

$v6 = IpLookupResponse::fromArray(fixture('lookup_2606_4700_4700__1111'));
assertSame(6, $v6->ipVersion, 'IPv6 ip_version is 6');
assertSame('2606:4700:4700::/48', $v6->matchedNetwork, 'IPv6 matched_network parsed');
assertSame('physical', $v6->geo->locationType, 'IPv6 location_type parsed');
assertSame(false, $v6->geo->isVirtualLocation, 'false is_virtual_location stays false');

// 8.8.8.8 omits security.is_relay entirely.
$g = IpLookupResponse::fromArray(fixture('lookup_8.8.8.8'));
assertSame(null, $g->security->isRelay, 'absent security.is_relay is null');
assertSame('Google LLC', $g->network->organization, '8.8.8.8 organization parsed');

// Unlicensed field families are omitted by the API.
$unlicensed = fixture('lookup_1.1.1.1');
unset($unlicensed['connection'], $unlicensed['security_extensions']);
$u = IpLookupResponse::fromArray($unlicensed);
assertSame(null, $u->connection, 'omitted connection block is null');
assertSame(null, $u->securityExtensions, 'omitted security_extensions block is null');

// Abstaining booleans are null, not false.
$abstain = fixture('lookup_1.1.1.1');
$abstain['security']['is_vpn'] = null;
$abstain['connection']['is_mobile'] = null;
$abstain['security_extensions']['abuse_velocity_score'] = null;
$a = IpLookupResponse::fromArray($abstain);
assertSame(null, $a->security->isVpn, 'null security.is_vpn stays null');
assertSame(null, $a->connection?->isMobile, 'null connection.is_mobile stays null');
assertSame(null, $a->securityExtensions?->abuseVelocityScore, 'null abuse_velocity_score stays null');

// Deprecated 1.0 property aliases still read the right values.
$deprecations = 0;
set_error_handler(static function (int $errno) use (&$deprecations): bool {
    if ($errno === E_USER_DEPRECATED) {
        $deprecations++;
        return true;
    }
    return false;
});
assertSame('CLOUDFLARENET - Cloudflare, Inc.', $v4->network->org, 'deprecated network->org aliases organization');
assertSame(true, $v4->security->isDatacenter, 'deprecated security->isDatacenter aliases isHosting');
assertSame(false, $v4->security->isTor, 'deprecated security->isTor aliases isTorExit');
assertSame(6, $v6->version, 'deprecated ->version aliases ipVersion');
restore_error_handler();
assertSame(4, $deprecations, 'each deprecated alias raises E_USER_DEPRECATED');

// ---------------------------------------------------------------------------
// 4. Bounded O(1) LRU + TTL cache
// ---------------------------------------------------------------------------
$cache = new LruTtlCache(new CacheOptions(enabled: true, maxEntries: 2, ttlSeconds: 10.0), 0);
$rec1 = IpLookupResponse::fromArray(lookupPayloadFor('1.1.1.1'));
$rec2 = IpLookupResponse::fromArray(lookupPayloadFor('8.8.8.8'));
$rec3 = IpLookupResponse::fromArray(lookupPayloadFor('9.9.9.9'));

$cache->set('1.1.1.1', $rec1, 100.0);
$cache->set('8.8.8.8', $rec2, 100.0);
assertSame('1.1.1.1', $cache->get('1.1.1.1', 101.0)?->ip, 'Cache hit promotes 1.1.1.1');
$cache->set('9.9.9.9', $rec3, 102.0);

assertSame(null, $cache->get('8.8.8.8', 103.0), 'LRU entry 8.8.8.8 evicted');
assertSame('1.1.1.1', $cache->get('1.1.1.1', 103.0)?->ip, 'Promoted entry 1.1.1.1 retained');
assertSame(null, $cache->get('1.1.1.1', 115.0), 'TTL expired entry evicted on access');
assertSame(1, $cache->stats()->evictions, 'Cache eviction counter incremented');

// ---------------------------------------------------------------------------
// 5. Client operations against the real API paths and bodies
// ---------------------------------------------------------------------------
$requests = [];
$client = new IpScopeClient(
    apiKey: TEST_API_KEY,
    minFreeHeadroomBytes: 0,
    customTransport: function (string $method, string $url, array $headers, ?string $body, float $timeout) use (&$requests): array {
        $requests[] = ['method' => $method, 'url' => $url, 'body' => $body, 'headers' => $headers];
        $path = rawurldecode((string) parse_url($url, PHP_URL_PATH));
        $rateHeaders = [
            'X-RateLimit-Scope' => 'user',
            'X-RateLimit-Limit' => '600',
            'X-RateLimit-Remaining' => '598',
            'X-RateLimit-Reset' => '42',
        ];

        if ($method === 'GET' && $path === '/v1/ip/1.1.1.1') {
            return ['status' => 200, 'headers' => $rateHeaders, 'body' => fixtureJson('lookup_1.1.1.1')];
        }
        if ($method === 'GET' && $path === '/v1/ip/2606:4700:4700::1111') {
            return ['status' => 200, 'headers' => $rateHeaders, 'body' => fixtureJson('lookup_2606_4700_4700__1111')];
        }
        if ($method === 'GET' && $path === '/v1/ip/me') {
            return ['status' => 200, 'headers' => [], 'body' => (string) json_encode(lookupPayloadFor('203.0.113.10'))];
        }
        if ($method === 'POST' && $path === '/v1/ip/batch') {
            /** @var array{ips: list<string>} $decoded */
            $decoded = json_decode((string) $body, true);
            $results = array_map('lookupPayloadFor', $decoded['ips']);
            return [
                'status' => 200,
                'headers' => $rateHeaders,
                'body' => (string) json_encode([
                    'dataset_version' => '2026-11-10',
                    'count' => count($results),
                    'results' => $results,
                ]),
            ];
        }
        if ($method === 'GET' && $path === '/v1/networks/1.1.1.0/24') {
            return ['status' => 200, 'headers' => $rateHeaders, 'body' => fixtureJson('network_1.1.1.0_24')];
        }
        if ($method === 'GET' && $path === '/v1/metadata/datasets') {
            return ['status' => 200, 'headers' => $rateHeaders, 'body' => fixtureJson('datasets')];
        }
        if ($method === 'POST' && $path === '/v1/feedback') {
            return ['status' => 201, 'headers' => $rateHeaders, 'body' => fixtureJson('feedback_response')];
        }
        if ($method === 'GET' && $path === '/v1/status') {
            return ['status' => 200, 'headers' => [], 'body' => fixtureJson('status')];
        }

        return ['status' => 404, 'headers' => [], 'body' => '{"message":"Cannot GET ' . $path . '","error":"Not Found","statusCode":404}'];
    }
);

assertSame('1.1.0', IpScopeClient::VERSION, 'client VERSION is 1.1.0');
$meta1 = $client->lookupIpWithMeta('1.1.1.1');
assertSame(false, $meta1->fromCache, 'First lookupIp is fetched from API');
assertSame(
    sprintf('ipscope-sdk-php/%s (PHP/%s)', HttpTransport::SDK_VERSION, PHP_VERSION),
    $requests[0]['headers']['User-Agent'],
    'User-Agent carries SDK version'
);
assertSame(TEST_API_KEY, $requests[0]['headers']['X-API-Key'], 'API key sent in X-API-Key');
assertSame('CLOUDFLARENET - Cloudflare, Inc.', $meta1->data->network->organization, 'lookupIp organization');
assertSame(600, $meta1->rateLimit?->limit, 'X-RateLimit-Limit parsed');
assertSame(598, $meta1->rateLimit?->remaining, 'X-RateLimit-Remaining parsed');
assertSame(42, $meta1->rateLimit?->resetAfterSeconds, 'X-RateLimit-Reset parsed as seconds until reset');
assertSame('user', $meta1->rateLimit?->scope, 'X-RateLimit-Scope parsed');
assertSame(42, $client->getLastRateLimit()?->resetEpochSeconds, 'deprecated resetEpochSeconds returns the same seconds value');
assertSame(null, $client->getLastRateLimit()?->creditsRemaining, 'deprecated creditsRemaining is always null');
assertSame(null, $client->getLastRateLimit()?->planTier, 'deprecated planTier is always null');

$meta2 = $client->lookupIpWithMeta('1.1.1.1');
assertSame(true, $meta2->fromCache, 'Second lookupIp served from LRU cache');
assertSame(1, count($requests), 'No extra HTTP request on cache hit');

$v6Live = $client->lookupIp('2606:4700:4700:0000:0000:0000:0000:1111');
assertSame(6, $v6Live->ipVersion, 'IPv6 lookup via canonicalized path');

// Batch lookup reuses cached 1.1.1.1 and only POSTs 8.8.8.8
$batch = $client->lookupBatch(['1.1.1.1', '8.8.8.8', '1.1.1.1']);
assertSame(2, $batch->count, 'Batch returns 2 unique results');
assertSame('1.1.1.1', $batch->results[0]->ip, 'First batch item is 1.1.1.1');
assertSame('8.8.8.8', $batch->results[1]->ip, 'Second batch item is 8.8.8.8');
assertSame('2026-11-10', $batch->datasetVersion, 'Batch dataset_version parsed');
assertSame('{"ips":["8.8.8.8"]}', end($requests)['body'], 'Batch POST only sent uncached 8.8.8.8');

$cachedOnly = $client->lookupBatch(['1.1.1.1']);
assertSame('2026-11-10', $cachedOnly->datasetVersion, 'All-cached batch carries dataset_version from records');

$streamIps = [];
for ($i = 1; $i <= 140; $i++) {
    $streamIps[] = sprintf('198.51.100.%d', $i);
}
$chunks = [];
foreach ($client->lookupBatchStream($streamIps) as $chunkResp) {
    $chunks[] = $chunkResp->count;
}
assertSame([100, 40], $chunks, 'lookupBatchStream yields 100 and 40 IP chunks');

$caller = $client->lookupCallerIp();
assertSame('203.0.113.10', $caller->ip, 'Caller IP resolved via /v1/ip/me');

$net = $client->lookupNetwork('1.1.1.42/24');
assertSame('1.1.1.0/24', $net->queriedCidr, 'network queried_cidr parsed (host bits masked)');
assertSame('1.1.1.0/24', $net->matchedNetwork, 'network matched_network parsed');
assertSame(4, $net->family, 'network family parsed');
assertSame(24, $net->bgpPrefixLength, 'network bgp_prefix_length parsed');
assertSame('2026-11-10', $net->datasetVersion, 'network dataset_version parsed');
assertSame('1.1.1.0/24', $net->record?->prefix, 'network record.prefix parsed');
assertSame('CLOUDFLARENET - Cloudflare, Inc.', $net->record?->organization, 'network record.organization parsed');
assertSame(true, $net->record?->isHosting, 'network record.isHosting parsed');
assertSame(null, $net->record?->isVirtualLocation, 'network record.isVirtualLocation null');
assertSame('hosting', $net->record?->connectionType, 'network record.connectionType parsed');
assertSame(0.85, $net->record?->geoConfidence, 'network record.geoConfidence parsed');
assertSame('Australia', $net->record?->locations->declaredLocation?->countryName, 'network record declared location parsed');
assertSame(null, $net->record?->locations->clientLocation, 'network record clientLocation null');
assertSame(['policy-routing-rdap-permitted', 'policy-rfc8805-public'], $net->record?->licensePolicyIds, 'network record licensePolicyIds parsed');
assertSame(14, $net->record?->abuseVelocityScore, 'network record integer abuseVelocityScore stays int');
assertSame(14, $net->lookup?->securityExtensions?->abuseVelocityScore, 'integer 0-100 abuse_velocity_score stays int');
assertSame('1.1.1.0', $net->lookup?->ip, 'network lookup parsed as IpLookupResponse');
assertSame(true, $net->lookup?->security->isHosting, 'network lookup security parsed');

$nullRecord = fixture('network_1.1.1.0_24');
$nullRecord['record'] = null;
assertSame(null, IpScope\Sdk\NetworkPrefixLookupResponse::fromArray($nullRecord)->record, 'null network record stays null');

$datasets = $client->getDatasetsMetadata();
assertSame('2026-11-10', $datasets->activeVersion, 'datasets active_version parsed');
assertSame('2026-11-09', $datasets->previousVersion, 'datasets previous_version parsed');
assertSame(2, count($datasets->snapshots), 'datasets snapshots parsed');
assertSame('ruleset-2026.11.1', $datasets->snapshots[0]->rulesetVersion, 'snapshot ruleset_version parsed');
assertSame(1043211, $datasets->snapshots[0]->ipv4PrefixCount, 'snapshot ipv4_prefix_count parsed');

$fb = $client->submitFeedback(new FeedbackSubmissionInput(
    prefixOrIp: '8.8.8.42/24',
    role: 'network_owner',
    issueType: 'wrong_city',
    requestedCorrection: ['city' => 'Mountain View', 'country_code' => 'US'],
    evidenceUrl: 'https://example.net/geofeed.csv',
));
$sent = json_decode((string) end($requests)['body'], true);
assertSame(
    [
        'prefix_or_ip' => '8.8.8.0/24',
        'role' => 'network_owner',
        'issue_type' => 'wrong_city',
        'requested_correction' => ['city' => 'Mountain View', 'country_code' => 'US'],
        'contact_consent' => false,
        'evidence_url' => 'https://example.net/geofeed.csv',
    ],
    $sent,
    'Feedback body matches the API schema'
);
assertSame('fb_3f9a2c71-b4e', $fb->id, 'Feedback id parsed');
assertSame('2026-11-10T09:15:42.118Z', $fb->createdAt, 'Feedback camelCase createdAt parsed');
assertSame('pending_review', $fb->status, 'Feedback status parsed');
assertSame('wrong_city', $fb->issueType, 'Feedback issue_type parsed');
assertSame(
    '2026-11-10T00:00:00Z',
    IpScope\Sdk\FeedbackSubmissionResponse::fromArray(['created_at' => '2026-11-10T00:00:00Z'])->createdAt,
    'Feedback snake_case created_at also accepted'
);

$client->submitFeedback(new FeedbackSubmissionInput(prefixOrIp: '8.8.8.8', role: 'user', issueType: 'other'));
assertSame('{"prefix_or_ip":"8.8.8.8","role":"user","issue_type":"other","requested_correction":{},"contact_consent":false}', end($requests)['body'], 'Empty requested_correction encodes as JSON object');

$requestsBefore = count($requests);
foreach ([
    ['role', new FeedbackSubmissionInput(prefixOrIp: '8.8.8.8', role: 'admin', issueType: 'other')],
    ['issueType', new FeedbackSubmissionInput(prefixOrIp: '8.8.8.8', role: 'user', issueType: 'wrong_asn')],
    ['evidenceUrl', new FeedbackSubmissionInput(prefixOrIp: '8.8.8.8', role: 'user', issueType: 'other', evidenceUrl: 'not a url')],
    ['contactEmail', new FeedbackSubmissionInput(prefixOrIp: '8.8.8.8', role: 'user', issueType: 'other', contactEmail: 'nobody')],
] as [$field, $bad]) {
    $field_ = null;
    try {
        $client->submitFeedback($bad);
    } catch (IpScopeValidationException $e) {
        $field_ = $e->field;
    }
    assertSame($field, $field_, "Invalid feedback {$field} rejected client-side");
}
assertSame($requestsBefore, count($requests), 'Invalid feedback never reaches the API');

$status = $client->getStatus();
assertSame('healthy', $status->status, 'Service status parsed');
assertSame('2026-11-10', $status->currentVersion(), 'Status snapshot.currentVersion parsed');
assertSame('2026-11-09', $status->snapshot?->previousVersion, 'Status snapshot.previousVersion parsed');

// ---------------------------------------------------------------------------
// 6. Retry on 429, deep JSON protection
// ---------------------------------------------------------------------------
$attempts = 0;
$retryClient = new IpScopeClient(
    apiKey: TEST_API_KEY,
    retry: new RetryOptions(maxRetries: 2, initialDelaySeconds: 0.005, maxDelaySeconds: 0.02),
    minFreeHeadroomBytes: 0,
    customTransport: function () use (&$attempts): array {
        $attempts++;
        if ($attempts === 1) {
            return [
                'status' => 429,
                'headers' => ['Retry-After' => '0.005', 'X-RateLimit-Remaining' => '0', 'X-RateLimit-Reset' => '1'],
                'body' => '{"statusCode":429,"message":"Rate limit exceeded for user"}',
            ];
        }
        return ['status' => 200, 'headers' => [], 'body' => (string) json_encode(lookupPayloadFor('9.9.9.9'))];
    }
);
$retried = $retryClient->lookupIp('9.9.9.9');
assertSame('9.9.9.9', $retried->ip, 'Client automatically retries on HTTP 429');
assertSame(2, $attempts, 'Exactly 2 attempts performed');

$deepJsonClient = new IpScopeClient(
    apiKey: TEST_API_KEY,
    retry: new RetryOptions(maxRetries: 0),
    minFreeHeadroomBytes: 0,
    customTransport: function (): array {
        $nested = str_repeat('{"a":', 25) . '1' . str_repeat('}', 25);
        return ['status' => 200, 'headers' => [], 'body' => $nested];
    }
);
$deepRejected = false;
try {
    $deepJsonClient->lookupIp('8.8.8.8');
} catch (IpScopeApiException $e) {
    $deepRejected = ($e->errorCode === 'IPSCOPE_INVALID_JSON');
}
assertTrue($deepRejected, 'Deeply nested JSON (>16 depth) is rejected');

$client->close();
assertSame(0, $client->getCacheStats()->size, 'close() resets cache state');

if ($failed > 0) {
    fwrite(STDERR, sprintf("\nFAILED: %d failed, %d passed.\n", $failed, $passed));
    exit(1);
}

echo sprintf("ALL %d PHP SDK TESTS PASSED (PHP %s)\n", $passed, PHP_VERSION);
