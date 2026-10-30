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

use IpScope\Sdk\IpScopeClient;
use IpScope\Sdk\IpScopeSecurity;

// Optional: inspect runtime patch status for CVE-2026-109618 / CVE-2026-109619
$advisory = IpScopeSecurity::getRuntimeAdvisoryStatus();
if (!$advisory['patched']) {
    error_log($advisory['recommendation']);
}

$client = new IpScopeClient(apiKey: '<public>:<private>');

// 1. Single IPv4 or IPv6 lookup (cached automatically in bounded LRU cache)
$ipInfo = $client->lookupIp('8.8.8.8');
echo $ipInfo->ip . ' ' . $ipInfo->geo->countryCode . ' AS' . $ipInfo->network->asn . PHP_EOL;
echo 'VPN: ' . ($ipInfo->security->isVpn ? 'true' : 'false') . ' Threat: ' . $ipInfo->security->threatLevel . PHP_EOL;

// 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
$batch = $client->lookupBatch(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']);
foreach ($batch->results as $record) {
    echo $record->ip . ' -> ' . $record->network->org . PHP_EOL;
}

// 3. Memory-bounded streaming batch lookup for 10,000+ IPs (constant O(chunk) RAM)
foreach ($client->lookupBatchStream($largeIpList) as $chunk) {
    foreach ($chunk->results as $record) {
        // Process each record with < 400 KB steady-state memory overhead
    }
}

// 4. Network CIDR prefix lookup
$prefix = $client->lookupNetwork('8.8.8.0/24');
echo $prefix->requestedCidr . ' matches: ' . $prefix->totalMatches . PHP_EOL;
```
