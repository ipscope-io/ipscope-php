# IPScope Official PHP Server-Side SDK (`ipscope/ipscope-php`)

Zero-dependency, memory-safe **PHP 8.2+** Server-Side SDK for the **IPScope IP Intelligence Platform**.

Scoped strictly to **IP intelligence operations** (single IP lookup, caller IP lookup, batch lookup, chunked/streaming batch lookup, network CIDR lookup, dataset metadata, geolocation/anonymity feedback submission, and service health status) with zero account, wallet, or billing dependencies.

---

## Security Hardening Against CVE-2026-109618 & CVE-2026-109619

On October 21, 2026, the PHP project disclosed two critical memory-corruption vulnerabilities (CVSS 9.2):
- **CVE-2026-109618 (`GHSA-w8hw-w9fx-j79w`)**: When PHP hits `memory_limit`, Zend Engine aborts execution via `zend_bailout()` (`longjmp`). If an out-of-memory (OOM) condition occurs while internal request structures are partially initialized, request cleanup can treat invalid pointers as valid and trigger memory corruption / RCE.
- **CVE-2026-109619 (`GHSA-6wmf-4rv5-p3rp`)**: Request-owned internal state can survive after its backing memory has been freed across subsequent requests handled by the same persistent worker (PHP-FPM, FrankenPHP, RoadRunner, Swoole).

### How `ipscope/ipscope-php` Protects Your Server
1. **Recommended PHP Versions**: Upgrade your PHP runtime to **`>=8.2.35`**, **`>=8.3.36`**, **`>=8.4.27`**, or **`>=8.5.12`**. You can verify your runtime programmatically via `IpScopeSecurity::getRuntimeAdvisoryStatus()`.
2. **Pre-OOM Heap Headroom Guard (`IpScopeSecurity::assertMemoryHeadroom`)**: Before buffering HTTP chunks, decoding JSON, or inserting into the cache, the SDK checks `memory_get_usage(true)` against `ini_get('memory_limit')`. If free heap headroom drops below `8 MiB` (`DEFAULT_MIN_FREE_BYTES`), the SDK aborts and throws a standard catchable userland `IpScopeMemoryLimitException` **before** Zend Engine ever hits `memory_limit` and calls `zend_bailout()`.
3. **Streaming cURL Write Callback (`CURLOPT_WRITEFUNCTION`)**: Instead of `CURLOPT_RETURNTRANSFER` (which buffers unbounded payloads in memory), the SDK inspects chunks on arrival and aborts transfers exceeding `2 MiB` (`MAX_RESPONSE_BYTES`).
4. **Bounded JSON Recursion Depth**: All JSON responses are decoded with `max_depth = 16` (`JSON_THROW_ON_ERROR`).
5. **Zero Static / Global State (`CVE-2026-109619`)**: The SDK uses zero mutable static properties or `$GLOBALS`, and `$client->close()` (also invoked in `__destruct()`) resets all internal buffers and caches between worker requests.

---

## Installation

```bash
composer require ipscope/ipscope-php
```

Or include the standalone autoloader directly:

```php
require_once '/path/to/sdks/php/autoload.php';
```

---

## Quick Start

```php
<?php

declare(strict_types=1);

use IpScope\Sdk\FeedbackSubmissionInput;
use IpScope\Sdk\IpScopeClient;
use IpScope\Sdk\IpScopeSecurity;

// Optional: inspect runtime patch status for CVE-2026-109618 / CVE-2026-109619
$advisory = IpScopeSecurity::getRuntimeAdvisoryStatus();
if (!$advisory['patched']) {
    error_log($advisory['recommendation']);
}

// API keys have the form "<public>:<private>" (a UUID, a colon, then a 43-character secret).
$client = new IpScopeClient(apiKey: '<public>:<private>');

// 1. Single IPv4 or IPv6 lookup (GET /v1/ip/{ip}; cached in a bounded LRU cache)
$ipInfo = $client->lookupIp('8.8.8.8');
echo $ipInfo->ip . ' IPv' . $ipInfo->ipVersion . ' ' . $ipInfo->geo->countryCode
    . ' AS' . $ipInfo->network->asn . ' ' . $ipInfo->network->organization . PHP_EOL;
// Security booleans are true, false, or null (null = not enough evidence).
echo 'VPN: ' . var_export($ipInfo->security->isVpn, true)
    . ' Hosting: ' . var_export($ipInfo->security->isHosting, true)
    . ' Tor exit: ' . var_export($ipInfo->security->isTorExit, true)
    . ' Anonymizer: ' . $ipInfo->security->anonymizerType . PHP_EOL;
// `connection` and `securityExtensions` are null unless your plan licenses them.
echo 'Connection: ' . ($ipInfo->connection?->connectionType ?? 'n/a')
    . ' Dataset: ' . $ipInfo->datasetVersion . PHP_EOL;

// 2. Your own public IP (GET /v1/ip/me)
$me = $client->lookupCallerIp();

// 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
$batch = $client->lookupBatch(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']);
foreach ($batch->results as $record) {
    echo $record->ip . ' -> ' . $record->network->organization . PHP_EOL;
}

// 4. Memory-bounded streaming batch lookup for 10,000+ IPs (constant O(chunk) RAM)
foreach ($client->lookupBatchStream($largeIpList) as $chunk) {
    foreach ($chunk->results as $record) {
        // Process each record with < 400 KB steady-state memory overhead
    }
}

// 5. Network CIDR prefix lookup (GET /v1/networks/{address}/{length})
$prefix = $client->lookupNetwork('8.8.8.0/24');
echo $prefix->queriedCidr . ' matched ' . $prefix->matchedNetwork
    . ' org: ' . ($prefix->record?->organization ?? 'n/a') . PHP_EOL;

// 6. Rate limits (per user): seconds until the window resets
$limits = $client->getLastRateLimit();
echo $limits?->remaining . '/' . $limits?->limit . ', resets in ' . $limits?->resetAfterSeconds . 's' . PHP_EOL;

// 7. Report a wrong answer (POST /v1/feedback)
$client->submitFeedback(new FeedbackSubmissionInput(
    prefixOrIp: '8.8.8.0/24',
    role: 'network_owner',          // network_owner | user | researcher
    issueType: 'wrong_city',        // see FeedbackSubmissionInput::ISSUE_TYPES
    requestedCorrection: ['city' => 'Mountain View'],
    evidenceUrl: 'https://example.net/geofeed.csv',
));

// 8. Service health and dataset versions
echo $client->getStatus()->currentVersion() . PHP_EOL;
echo $client->getDatasetsMetadata()->activeVersion . PHP_EOL;
```

Upgrading from 1.0? See [CHANGELOG.md](CHANGELOG.md).
