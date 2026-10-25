<?php

declare(strict_types=1);

namespace IpScope\Sdk;

use Generator;

/**
 * Official Server-Side PHP 8.2+ Client for the IPScope IP Intelligence Platform.
 *
 * Scoped strictly to IP intelligence operations (single IP lookup, caller IP lookup,
 * batch lookup, chunked/streaming batch lookup, CIDR network prefix lookup, dataset metadata,
 * geolocation/anonymity feedback submission, and service health status).
 *
 * Hardened against CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)
 * via pre-allocation heap headroom checks, streaming 2 MiB cURL response ceilings, bounded
 * JSON decoding depth (16), and zero mutable static/global state.
 */
final class IpScopeClient
{
    public const MAX_BATCH_SIZE = IpScopeValidator::MAX_BATCH_SIZE;
    public const MAX_RESPONSE_BYTES = HttpTransport::MAX_RESPONSE_BYTES;

    private HttpTransport $transport;
    private LruTtlCache $cache;

    /**
     * @param null|callable(string, string, array<string, string>, ?string, float): array{status: int, headers?: array<string, string>, body: string} $customTransport
     */
    public function __construct(
        string $apiKey,
        string $baseUrl = HttpTransport::DEFAULT_BASE_URL,
        float $timeoutSeconds = HttpTransport::DEFAULT_TIMEOUT_SECONDS,
        ?RetryOptions $retry = null,
        ?CacheOptions $cache = null,
        ?string $userAgent = null,
        int $minFreeHeadroomBytes = IpScopeSecurity::DEFAULT_MIN_FREE_BYTES,
        ?callable $customTransport = null
    ) {
        $this->transport = new HttpTransport(
            apiKey: $apiKey,
            baseUrl: $baseUrl,
            timeoutSeconds: $timeoutSeconds,
            retry: $retry,
            userAgent: $userAgent,
            minFreeHeadroomBytes: $minFreeHeadroomBytes,
            customTransport: $customTransport,
        );
        $this->cache = new LruTtlCache($cache, $minFreeHeadroomBytes);
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * Releases internal transport handles and clears cached state so zero request-owned
     * data survives across worker requests (mitigating CVE-2026-109619).
     */
    public function close(): void
    {
        $this->cache->clear();
        $this->transport->close();
    }

    /**
     * Looks up full IP intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/{ip}`).
     */
    public function lookupIp(string $ip, ?RequestOptions $options = null): IpLookupResponse
    {
        return $this->lookupIpWithMeta($ip, $options)->data;
    }

    /**
     * Looks up full IP intelligence for a single IPv4 or IPv6 address along with
     * rate-limit headers and cache hit metadata.
     */
    public function lookupIpWithMeta(string $ip, ?RequestOptions $options = null): IpScopeResultWithMeta
    {
        $canonicalIp = IpScopeValidator::validateIpAddress($ip);
        $bypassCache = $options?->bypassCache ?? false;

        if (!$bypassCache) {
            $cached = $this->cache->get($canonicalIp);
            if ($cached !== null) {
                return new IpScopeResultWithMeta(
                    data: $cached,
                    rateLimit: $this->transport->getLastRateLimit(),
                    fromCache: true,
                );
            }
        }

        $path = '/v1/ip/' . rawurlencode($canonicalIp);
        $raw = $this->transport->requestJson('GET', $path, null, $options);
        $record = IpLookupResponse::fromArray($raw['data']);

        if (!$bypassCache) {
            $this->cache->set($canonicalIp, $record);
            if ($record->ip !== '' && $record->ip !== $canonicalIp) {
                $this->cache->set($record->ip, $record);
            }
        }

        return new IpScopeResultWithMeta(
            data: $record,
            rateLimit: $raw['rateLimit'],
            fromCache: false,
        );
    }

    /**
     * Resolves IP intelligence for the caller's own public IP address (`GET /v1/ip`).
     */
    public function lookupCallerIp(?RequestOptions $options = null): IpLookupResponse
    {
        $raw = $this->transport->requestJson('GET', '/v1/ip', null, $options);
        $record = IpLookupResponse::fromArray($raw['data']);
        if (!($options?->bypassCache ?? false) && $record->ip !== '') {
            $this->cache->set($record->ip, $record);
        }
        return $record;
    }

    /**
     * Performs a batch IP lookup (`POST /v1/ip/batch`) for up to 100 IP addresses.
     * Automatically deduplicates input IPs, reuses cached entries from the LRU cache,
     * and backfills newly fetched records into the cache.
     *
     * @param list<string> $ips
     */
    public function lookupBatch(array $ips, ?RequestOptions $options = null): BatchLookupResponse
    {
        $uniqueIps = IpScopeValidator::validateAndDeduplicateBatchIps($ips, self::MAX_BATCH_SIZE);
        $bypassCache = $options?->bypassCache ?? false;

        /** @var array<string, IpLookupResponse> $resolvedMap */
        $resolvedMap = [];
        $missingIps = [];

        if (!$bypassCache && $this->cache->isEnabled()) {
            foreach ($uniqueIps as $ip) {
                $cached = $this->cache->get($ip);
                if ($cached !== null) {
                    $resolvedMap[$ip] = $cached;
                } else {
                    $missingIps[] = $ip;
                }
            }
        } else {
            $missingIps = $uniqueIps;
        }

        if ($missingIps !== []) {
            $raw = $this->transport->requestJson(
                'POST',
                '/v1/ip/batch',
                ['ips' => $missingIps],
                $options
            );
            $batchResp = BatchLookupResponse::fromArray($raw['data']);

            foreach ($batchResp->results as $idx => $record) {
                $requestedKey = $missingIps[$idx] ?? $record->ip;
                $resolvedMap[$requestedKey] = $record;
                if ($record->ip !== '') {
                    $resolvedMap[$record->ip] = $record;
                }
                if (!$bypassCache) {
                    $this->cache->set($requestedKey, $record);
                    if ($record->ip !== '' && $record->ip !== $requestedKey) {
                        $this->cache->set($record->ip, $record);
                    }
                }
            }
        }

        $orderedResults = [];
        foreach ($uniqueIps as $ip) {
            if (isset($resolvedMap[$ip])) {
                $orderedResults[] = $resolvedMap[$ip];
            }
        }

        return new BatchLookupResponse(
            count: count($orderedResults),
            results: $orderedResults,
        );
    }

    /**
     * Splits an arbitrarily large list of IP addresses into chunks of up to 100 unique IPs
     * and merges the results into a single `BatchLookupResponse`.
     *
     * @param list<string> $ips
     */
    public function lookupBatchChunked(array $ips, ?RequestOptions $options = null): BatchLookupResponse
    {
        $merged = [];
        foreach ($this->lookupBatchStream($ips, $options) as $chunkResponse) {
            foreach ($chunkResponse->results as $record) {
                $merged[] = $record;
            }
        }
        return new BatchLookupResponse(
            count: count($merged),
            results: $merged,
        );
    }

    /**
     * Memory-bounded streaming generator that yields `BatchLookupResponse` chunks of up to
     * 100 unique IP addresses at a time with constant `O(chunk)` RAM usage.
     *
     * @param iterable<string> $ips
     * @return Generator<int, BatchLookupResponse>
     */
    public function lookupBatchStream(iterable $ips, ?RequestOptions $options = null): Generator
    {
        $chunk = [];
        $seenInChunk = [];
        $yieldedAny = false;

        foreach ($ips as $rawIp) {
            if (!is_string($rawIp)) {
                throw new IpScopeValidationException('Expected string IP address in lookupBatchStream().', 'ips');
            }
            $canonical = IpScopeValidator::validateIpAddress($rawIp, 'ips');
            if (isset($seenInChunk[$canonical])) {
                continue;
            }
            $seenInChunk[$canonical] = true;
            $chunk[] = $canonical;

            if (count($chunk) >= self::MAX_BATCH_SIZE) {
                $yieldedAny = true;
                yield $this->lookupBatch($chunk, $options);
                $chunk = [];
                $seenInChunk = [];
            }
        }

        if ($chunk !== []) {
            $yieldedAny = true;
            yield $this->lookupBatch($chunk, $options);
        } elseif (!$yieldedAny) {
            throw new IpScopeValidationException(
                'Batch IP stream must contain at least 1 IP address.',
                'ips'
            );
        }
    }

    /**
     * Looks up BGP/CIDR network prefix intelligence (`GET /v1/network/{address}/{prefixLength}`).
     */
    public function lookupNetwork(string $cidr, ?RequestOptions $options = null): NetworkPrefixLookupResponse
    {
        $parsed = IpScopeValidator::validateCidrPrefix($cidr);
        $path = sprintf(
            '/v1/network/%s/%d',
            rawurlencode($parsed['address']),
            $parsed['prefixLength']
        );
        $raw = $this->transport->requestJson('GET', $path, null, $options);
        return NetworkPrefixLookupResponse::fromArray($raw['data']);
    }

    /**
     * Retrieves active IP intelligence dataset snapshots metadata (`GET /v1/datasets/metadata`).
     */
    public function getDatasetsMetadata(?RequestOptions $options = null): DatasetsMetadataResponse
    {
        $raw = $this->transport->requestJson('GET', '/v1/datasets/metadata', null, $options);
        return DatasetsMetadataResponse::fromArray($raw['data']);
    }

    /**
     * Submits an IP geolocation or anonymity correction (`POST /v1/feedback`).
     */
    public function submitFeedback(
        FeedbackSubmissionInput $feedback,
        ?RequestOptions $options = null
    ): FeedbackSubmissionResponse {
        $trimmed = trim($feedback->ipOrCidr);
        if ($trimmed === '') {
            throw new IpScopeValidationException('ipOrCidr must not be empty.', 'ipOrCidr');
        }
        if (str_contains($trimmed, '/')) {
            $normalized = IpScopeValidator::validateCidrPrefix($trimmed)['canonicalCidr'];
        } else {
            $normalized = IpScopeValidator::validateIpAddress($trimmed, 'ipOrCidr');
        }

        $payload = $feedback->toArray();
        $payload['ip_or_cidr'] = $normalized;

        $raw = $this->transport->requestJson('POST', '/v1/feedback', $payload, $options);
        return FeedbackSubmissionResponse::fromArray($raw['data']);
    }

    /**
     * Queries the IPScope API health status (`GET /v1/status`).
     */
    public function getStatus(?RequestOptions $options = null): ServiceStatusResponse
    {
        $raw = $this->transport->requestJson('GET', '/v1/status', null, $options);
        return ServiceStatusResponse::fromArray($raw['data']);
    }

    /**
     * Returns the most recent rate-limit metadata observed from `x-ratelimit-*` headers.
     */
    public function getLastRateLimit(): ?RateLimitMetadata
    {
        return $this->transport->getLastRateLimit();
    }

    /**
     * Returns current bounded LRU cache statistics.
     */
    public function getCacheStats(): CacheStats
    {
        return $this->cache->stats();
    }

    /**
     * Clears all entries and resets statistics in the in-memory LRU cache.
     */
    public function clearCache(): void
    {
        $this->cache->clear();
    }
}
