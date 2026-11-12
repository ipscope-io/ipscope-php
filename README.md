<div align="center">
  <br />
  <a href="https://ipscope.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" />
      <img alt="ipscope" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" height="32" />
    </picture>
  </a>
  <h1>ipscope/ipscope-php</h1>
  <p><strong>Official zero-dependency, memory-safe PHP 8.2+ server SDK for ipscope — IP geolocation, BGP ASN, and VPN/proxy detection</strong></p>
  <p>
    <a href="https://packagist.org/packages/ipscope/ipscope-php"><img src="https://img.shields.io/packagist/v/ipscope/ipscope-php.svg?style=flat-square&label=packagist&color=0f172a" alt="Packagist version" /></a>
    <img src="https://img.shields.io/badge/php-%3E%3D8.2-0f172a?style=flat-square" alt="PHP >= 8.2" />
    <img src="https://img.shields.io/badge/dependencies-zero-0f172a?style=flat-square" alt="Zero dependencies" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-0f172a?style=flat-square" alt="MIT licence" /></a>
    <a href="https://ipscope.io/docs/sdks/php"><img src="https://img.shields.io/badge/docs-ipscope.io-0f172a?style=flat-square" alt="Documentation" /></a>
  </p>
  <br />
  <a href="https://ipscope.io">
    <img alt="ipscope PHP SDK" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/banner.webp" width="100%" />
  </a>
</div>

<br />

## What is this

`ipscope/ipscope-php` is the official, zero-external-dependency, memory-safe PHP 8.2+ server SDK for [ipscope](https://ipscope.io). Built strictly on `ext-curl` and `ext-json`, it queries the [ipscope REST API](https://ipscope.io/products/api) for physical and declared [IP geolocation](https://ipscope.io/products/geolocation), [BGP origin ASN and prefix routing](https://ipscope.io/products/network), and [VPN, residential proxy, Tor exit, and relay detection](https://ipscope.io/products/privacy).

Every `IpScopeClient` includes a bounded `O(1)` LRU + TTL cache (`maxEntries: 512` default, `< 400 KB` memory footprint), a streaming `CURLOPT_WRITEFUNCTION` `2 MiB` ceiling, bounded JSON recursion depth (`16`), and pre-OOM heap headroom guards designed specifically for persistent workers (PHP-FPM, FrankenPHP, RoadRunner, Swoole, Laravel Octane). For offline in-process lookups in PHP, see our [downloadable MMDB databases](https://ipscope.io/docs/databases/mmdb).

---

## Getting started

### 1. Get an API key

Create a free account at [dashboard.ipscope.io](https://dashboard.ipscope.io/auth/login) and copy your server API key (`<public>:<private>`).

### 2. Install the package

```bash
composer require ipscope/ipscope-php
```

Or include the standalone autoloader directly:

```php
require_once '/path/to/sdks/php/autoload.php';
```

### 3. Look up an IP address

```php
<?php

declare(strict_types=1);

use IpScope\Sdk\IpScopeClient;

$client = new IpScopeClient(apiKey: getenv('IPSCOPE_API_KEY') ?: '<public>:<private>');

$info = $client->lookupIp('8.8.8.8');
echo $info->ip . ' ' . $info->geo->countryCode . ' AS' . $info->network->asn . ' ' . $info->network->organization . PHP_EOL;
```

---

## Contents

- [Lookups](#lookups)
- [Streaming large IP lists](#streaming-large-ip-lists)
- [Network CIDR prefix lookups](#network-cidr-prefix-lookups)
- [Rate-limit metadata](#rate-limit-metadata)
- [Submitting feedback](#submitting-feedback)
- [Memory & worker hardening](#memory--worker-hardening)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Help](#help)
- [Licence](#licence)

---

## Lookups

```php
<?php

declare(strict_types=1);

use IpScope\Sdk\IpScopeClient;

$client = new IpScopeClient(apiKey: '<public>:<private>');

// 1. Single IPv4 or IPv6 lookup (cached in bounded LRU)
$ipInfo = $client->lookupIp('8.8.8.8');
echo $ipInfo->ip . ' IPv' . $ipInfo->ipVersion . ' ' . $ipInfo->geo->countryCode
    . ' AS' . $ipInfo->network->asn . ' ' . $ipInfo->network->organization . PHP_EOL;
// Security booleans are true, false, or null (null = not enough evidence)
echo 'VPN: ' . var_export($ipInfo->security->isVpn, true)
    . ' Hosting: ' . var_export($ipInfo->security->isHosting, true)
    . ' Tor exit: ' . var_export($ipInfo->security->isTorExit, true)
    . ' Anonymizer: ' . $ipInfo->security->anonymizerType . PHP_EOL;

// 2. Caller IP lookup (GET /v1/ip/me)
$me = $client->lookupCallerIp();

// 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
$batch = $client->lookupBatch(['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']);
foreach ($batch->results as $record) {
    echo $record->ip . ' -> ' . $record->network->organization . PHP_EOL;
}
```

---

## Streaming large IP lists

Enrich 10,000+ IP addresses with `< 400 KB` steady-state memory overhead using `lookupBatchStream`:

```php
foreach ($client->lookupBatchStream($largeIpList) as $chunk) {
    foreach ($chunk->results as $record) {
        echo $record->ip . ' ' . $record->geo->countryCode . PHP_EOL;
    }
}
```

---

## Network CIDR prefix lookups

Inspect the longest-matching routed BGP prefix and its base address intelligence via `lookupNetwork`:

```php
$prefix = $client->lookupNetwork('8.8.8.0/24');
echo $prefix->queriedCidr . ' matched ' . $prefix->matchedNetwork
    . ' org: ' . ($prefix->record?->organization ?? 'n/a') . PHP_EOL;
```

---

## Rate-limit metadata

Inspect the parsed `X-RateLimit-*` headers from the last request or inspect service health and dataset versions:

```php
$limits = $client->getLastRateLimit();
echo $limits?->remaining . '/' . $limits?->limit . ', resets in ' . $limits?->resetAfterSeconds . 's' . PHP_EOL;

echo $client->getStatus()->currentVersion() . PHP_EOL;
echo $client->getDatasetsMetadata()->activeVersion . PHP_EOL;
```

---

## Submitting feedback

Report outdated geolocation or anonymity classifications directly via `submitFeedback`:

```php
use IpScope\Sdk\FeedbackSubmissionInput;

$client->submitFeedback(new FeedbackSubmissionInput(
    prefixOrIp: '8.8.8.0/24',
    role: 'network_owner',          // network_owner | user | researcher
    issueType: 'wrong_city',        // see FeedbackSubmissionInput::ISSUE_TYPES
    requestedCorrection: ['city' => 'Mountain View'],
    evidenceUrl: 'https://example.net/geofeed.csv',
));
```

---

## Memory & worker hardening

`ipscope/ipscope-php` is hardened against PHP memory-limit bailout and persistent-worker state retention vulnerabilities (`CVE-2026-109618` / `CVE-2026-109619`):

1. **Pre-OOM Heap Headroom Guard (`IpScopeSecurity::assertMemoryHeadroom`)**: Before buffering HTTP chunks, decoding JSON, or inserting into the cache, the SDK checks `memory_get_usage(true)` against `ini_get('memory_limit')`. If free heap headroom drops below `8 MiB` (`DEFAULT_MIN_FREE_BYTES`), the SDK throws a catchable `IpScopeMemoryLimitException` before Zend Engine ever hits `memory_limit` and calls `zend_bailout()`.
2. **Streaming cURL Write Callback (`CURLOPT_WRITEFUNCTION`)**: Inspects chunks on arrival and aborts transfers exceeding `2 MiB` (`MAX_RESPONSE_BYTES`).
3. **Zero Static / Global State**: Uses zero mutable static properties or `$GLOBALS`, and `$client->close()` resets all internal buffers and caches between worker requests.

---

## Requirements

- PHP 8.2 or later (`>=8.2.35`, `>=8.3.36`, `>=8.4.27`, or `>=8.5.12` recommended)
- `ext-curl` and `ext-json`

---

## Documentation

| Topic | Link |
| :--- | :--- |
| PHP SDK guide | [ipscope.io/docs/sdks/php](https://ipscope.io/docs/sdks/php) |
| REST API overview | [ipscope.io/docs/api/overview](https://ipscope.io/docs/api/overview) |
| Single & batch IP lookups | [ipscope.io/docs/api/single-ip](https://ipscope.io/docs/api/single-ip) |
| Network CIDR prefix lookups | [ipscope.io/docs/api/network-prefix](https://ipscope.io/docs/api/network-prefix) |
| Errors & rate limits | [ipscope.io/docs/api/errors](https://ipscope.io/docs/api/errors) |
| Downloadable MMDB databases | [ipscope.io/docs/databases/mmdb](https://ipscope.io/docs/databases/mmdb) |

---

## Help

- Bugs and feature requests: [open an issue](https://github.com/ipscope-io/ipscope-php/issues)
- Account, billing and integration questions: [contact@ipscope.io](mailto:contact@ipscope.io)
- Security vulnerabilities: see the [security policy](https://github.com/ipscope-io/.github/blob/main/SECURITY.md)

---

## Licence

[MIT](LICENSE). Made by [ipscope](https://ipscope.io).
