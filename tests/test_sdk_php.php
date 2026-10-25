<?php

declare(strict_types=1);

require_once __DIR__ . '/../autoload.php';

use IpScope\Sdk\CacheOptions;
use IpScope\Sdk\FeedbackSubmissionInput;
use IpScope\Sdk\IpScopeApiException;
use IpScope\Sdk\IpScopeAuthenticationException;
use IpScope\Sdk\IpScopeClient;
use IpScope\Sdk\IpScopeMemoryLimitException;
use IpScope\Sdk\IpScopeRateLimitException;
use IpScope\Sdk\IpScopeSecurity;
use IpScope\Sdk\IpScopeValidationException;
use IpScope\Sdk\IpScopeValidator;
use IpScope\Sdk\LruTtlCache;
use IpScope\Sdk\RequestOptions;
use IpScope\Sdk\RetryOptions;

$passed = 0;
$failed = 0;

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
 * @param string $ip
 * @return array<string, mixed>
 */
function sampleIpPayload(string $ip = '8.8.8.8'): array
{
    return [
        'ip' => $ip,
        'version' => str_contains($ip, ':') ? 6 : 4,
        'is_bogon' => false,
        'bogon_type' => null,
        'geo' => [
            'country_code' => 'US',
            'country_name' => 'United States',
            'region_code' => 'CA',
            'region_name' => 'California',
            'city' => 'Mountain View',
            'postal_code' => '94043',
            'latitude' => 37.4056,
            'longitude' => -122.0775,
            'timezone' => 'America/Los_Angeles',
            'accuracy_radius_km' => 20,
        ],
        'network' => [
            'asn' => 15169,
            'asn_name' => 'GOOGLE',
            'org' => 'Google LLC',
            'isp' => 'Google LLC',
            'connection_type' => 'datacenter',
            'bgp_prefix' => '8.8.8.0/24',
            'rir' => 'ARIN',
        ],
        'security' => [
            'is_vpn' => false,
            'is_proxy' => false,
            'is_tor' => false,
            'is_datacenter' => true,
            'is_relay' => false,
            'threat_level' => 'low',
            'threat_types' => [],
        ],
        'connection' => [
            'usage_type' => 'hosting',
            'company_type' => 'technology',
            'carrier_name' => null,
            'mcc' => null,
            'mnc' => null,
            'domain' => 'google.com',
            'route' => '8.8.8.0/24',
            'allocated_date' => '2014-03-14',
            'registry_status' => 'assigned',
        ],
        'security_extensions' => [
            'vpn_provider' => null,
            'proxy_type' => null,
            'threat_score' => 5,
            'is_abuser' => false,
            'is_bot' => false,
            'is_bogon' => false,
        ],
        'updated_at' => '2026-10-25T00:00:00Z',
    ];
}

// ---------------------------------------------------------------------------
// 1. CVE-2026-109618 & CVE-2026-109619 Security & Memory-Safety Guard Tests
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
    // Simulate 60 MiB used out of 64 MiB limit with 8 MiB required headroom
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
assertTrue($oomCaught, 'Pre-OOM guard throws IpScopeMemoryLimitException before Zend fatal bailout');

// ---------------------------------------------------------------------------
// 2. Zero-DNS Validator Tests
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
// 3. Bounded O(1) LRU + TTL Cache Tests
// ---------------------------------------------------------------------------
$cache = new LruTtlCache(new CacheOptions(enabled: true, maxEntries: 2, ttlSeconds: 10.0), 0);
$rec1 = IpScope\Sdk\IpLookupResponse::fromArray(sampleIpPayload('1.1.1.1'));
$rec2 = IpScope\Sdk\IpLookupResponse::fromArray(sampleIpPayload('8.8.8.8'));
$rec3 = IpScope\Sdk\IpLookupResponse::fromArray(sampleIpPayload('9.9.9.9'));

$cache->set('1.1.1.1', $rec1, 100.0);
$cache->set('8.8.8.8', $rec2, 100.0);
// Promote 1.1.1.1 so 8.8.8.8 becomes least-recently-used
assertSame('1.1.1.1', $cache->get('1.1.1.1', 101.0)?->ip, 'Cache hit promotes 1.1.1.1');
$cache->set('9.9.9.9', $rec3, 102.0);

assertSame(null, $cache->get('8.8.8.8', 103.0), 'LRU entry 8.8.8.8 evicted');
assertSame('1.1.1.1', $cache->get('1.1.1.1', 103.0)?->ip, 'Promoted entry 1.1.1.1 retained');
assertSame(null, $cache->get('1.1.1.1', 115.0), 'TTL expired entry evicted on access');
assertSame(1, $cache->stats()->evictions, 'Cache eviction counter incremented');

// ---------------------------------------------------------------------------
// 4. Client Operations, Batch Cache Reuse, Streaming & Resilience Tests
// ---------------------------------------------------------------------------
$requests = [];
$client = new IpScopeClient(
    apiKey: 'ips_live_test_key_123456',
    minFreeHeadroomBytes: 0,
    customTransport: function (string $method, string $url, array $headers, ?string $body, float $timeout) use (&$requests): array {
        $requests[] = ['method' => $method, 'url' => $url, 'body' => $body];
        $path = (string) parse_url($url, PHP_URL_PATH);

        if ($method === 'GET' && $path === '/v1/ip/8.8.8.8') {
            return [
                'status' => 200,
                'headers' => [
                    'x-ratelimit-limit' => '1000',
                    'x-ratelimit-remaining' => '998',
                    'x-ratelimit-reset' => '1760000000',
                    'x-ratelimit-credits-remaining' => '49990',
                    'x-ratelimit-tier' => 'pro',
                ],
                'body' => (string) json_encode(sampleIpPayload('8.8.8.8')),
            ];
        }

        if ($method === 'GET' && $path === '/v1/ip') {
            return [
                'status' => 200,
                'headers' => [],
                'body' => (string) json_encode(sampleIpPayload('203.0.113.10')),
            ];
        }

        if ($method === 'POST' && $path === '/v1/ip/batch') {
            /** @var array{ips: list<string>} $decoded */
            $decoded = json_decode((string) $body, true);
            $results = [];
            foreach ($decoded['ips'] as $ip) {
                $results[] = sampleIpPayload($ip);
            }
            return [
                'status' => 200,
                'headers' => [],
                'body' => (string) json_encode(['count' => count($results), 'results' => $results]),
            ];
        }

        if ($method === 'GET' && $path === '/v1/network/8.8.8.0/24') {
            return [
                'status' => 200,
                'headers' => [],
                'body' => (string) json_encode([
                    'requested_cidr' => '8.8.8.0/24',
                    'exact_match' => [
                        'network_cidr' => '8.8.8.0/24',
                        'ip_version' => 4,
                        'geo' => sampleIpPayload()['geo'],
                        'network' => sampleIpPayload()['network'],
                        'security' => sampleIpPayload()['security'],
                        'updated_at' => '2026-10-25T00:00:00Z',
                    ],
                    'enclosing_prefix' => null,
                    'overlapping_prefixes' => [],
                    'total_matches' => 1,
                ]),
            ];
        }

        if ($method === 'GET' && $path === '/v1/datasets/metadata') {
            return [
                'status' => 200,
                'headers' => [],
                'body' => (string) json_encode([
                    'count' => 1,
                    'active_datasets' => [[
                        'source' => 'ipscope-core',
                        'version_tag' => '2026.10.25',
                        'checksum_sha256' => 'abc123',
                        'record_count' => 1250000,
                        'activated_at' => '2026-10-25T00:00:00Z',
                        'created_at' => '2026-10-25T00:00:00Z',
                    ]],
                ]),
            ];
        }

        if ($method === 'POST' && $path === '/v1/feedback') {
            return [
                'status' => 201,
                'headers' => [],
                'body' => (string) json_encode([
                    'id' => 'fb_01',
                    'ip_or_cidr' => '8.8.8.8',
                    'status' => 'pending_review',
                    'created_at' => '2026-10-25T00:00:00Z',
                ]),
            ];
        }

        if ($method === 'GET' && $path === '/v1/status') {
            return [
                'status' => 200,
                'headers' => [],
                'body' => (string) json_encode([
                    'status' => 'ok',
                    'service' => 'ipscope-api',
                    'version' => '2.0.0',
                    'uptime_seconds' => 86400.5,
                    'timestamp' => '2026-10-25T00:00:00Z',
                ]),
            ];
        }

        return ['status' => 404, 'headers' => [], 'body' => '{"message":"Not Found"}'];
    }
);

$meta1 = $client->lookupIpWithMeta('8.8.8.8');
assertSame(false, $meta1->fromCache, 'First lookupIp is fetched from API');
assertSame('US', $meta1->data->geo->countryCode, 'Country code mapped');
assertSame(15169, $meta1->data->network->asn, 'ASN mapped');
assertSame(998, $meta1->rateLimit?->remaining, 'RateLimit remaining parsed');
assertSame('pro', $client->getLastRateLimit()?->planTier, 'Plan tier stored on client');

$meta2 = $client->lookupIpWithMeta('8.8.8.8');
assertSame(true, $meta2->fromCache, 'Second lookupIp served from LRU cache');
assertSame(1, count($requests), 'No extra HTTP request on cache hit');

// Batch lookup should reuse cached 8.8.8.8 and only POST 1.1.1.1
$batch = $client->lookupBatch(['8.8.8.8', '1.1.1.1', '8.8.8.8']);
assertSame(2, $batch->count, 'Batch returns 2 unique results');
assertSame('8.8.8.8', $batch->results[0]->ip, 'First batch item is 8.8.8.8');
assertSame('1.1.1.1', $batch->results[1]->ip, 'Second batch item is 1.1.1.1');
assertSame('{"ips":["1.1.1.1"]}', $requests[1]['body'], 'Batch POST only sent uncached 1.1.1.1');

// Streaming batch generator over 140 IPs (100 + 40 chunks)
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
assertSame('203.0.113.10', $caller->ip, 'Caller IP resolved');

$net = $client->lookupNetwork('8.8.8.42/24');
assertSame('8.8.8.0/24', $net->requestedCidr, 'CIDR lookup normalizes host bits');
assertSame(1, $net->totalMatches, 'CIDR totalMatches parsed');

$datasets = $client->getDatasetsMetadata();
assertSame('ipscope-core', $datasets->activeDatasets[0]->source, 'Dataset source parsed');

$fb = $client->submitFeedback(new FeedbackSubmissionInput(
    ipOrCidr: '8.8.8.8',
    suggestedCountryCode: 'US',
    notes: 'Anycast node'
));
assertSame('fb_01', $fb->id, 'Feedback submission ID parsed');

$status = $client->getStatus();
assertSame('ok', $status->status, 'Service status parsed');

// ---------------------------------------------------------------------------
// 5. Retry on 429, Oversized Response Ceiling, and Deep JSON Protection
// ---------------------------------------------------------------------------
$attempts = 0;
$retryClient = new IpScopeClient(
    apiKey: 'ips_live_retry_key_123456',
    retry: new RetryOptions(maxRetries: 2, initialDelaySeconds: 0.005, maxDelaySeconds: 0.02),
    minFreeHeadroomBytes: 0,
    customTransport: function () use (&$attempts): array {
        $attempts++;
        if ($attempts === 1) {
            return [
                'status' => 429,
                'headers' => ['retry-after' => '0.005'],
                'body' => '{"message":"Rate limit exceeded"}',
            ];
        }
        return [
            'status' => 200,
            'headers' => [],
            'body' => (string) json_encode(sampleIpPayload('9.9.9.9')),
        ];
    }
);
$retried = $retryClient->lookupIp('9.9.9.9');
assertSame('9.9.9.9', $retried->ip, 'Client automatically retries on HTTP 429');
assertSame(2, $attempts, 'Exactly 2 attempts performed');

// Deep JSON nesting bomb (>16 levels) rejected
$deepJsonClient = new IpScopeClient(
    apiKey: 'ips_live_deep_json_123456',
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
assertTrue($deepRejected, 'Deeply nested JSON (>16 depth) is rejected before exhausting stack/heap');

// Clean up worker state (CVE-2026-109619 mitigation)
$client->close();
assertSame(0, $client->getCacheStats()->size, 'close() resets cache state between worker requests');

if ($failed > 0) {
    fwrite(STDERR, sprintf("\nFAILED: %d failed, %d passed.\n", $failed, $passed));
    exit(1);
}

echo sprintf("ALL %d PHP SDK TESTS PASSED (PHP %s)\n", $passed, PHP_VERSION);
