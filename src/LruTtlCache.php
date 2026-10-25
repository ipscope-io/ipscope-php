<?php

declare(strict_types=1);

namespace IpScope\Sdk;

/**
 * Bounded O(1) LRU + TTL in-memory cache for IP intelligence records.
 *
 * Uses PHP's ordered associative array semantics for O(1) access, O(1) promotion,
 * and O(1) eviction of the oldest entry (`array_key_first`).
 */
final class LruTtlCache
{
    private bool $enabled;
    private int $maxEntries;
    private float $ttlSeconds;
    private int $minFreeHeadroomBytes;

    /** @var array<string, array{value: IpLookupResponse, expiresAt: float}> */
    private array $store = [];

    private int $hits = 0;
    private int $misses = 0;
    private int $evictions = 0;

    public function __construct(
        ?CacheOptions $options = null,
        int $minFreeHeadroomBytes = IpScopeSecurity::DEFAULT_MIN_FREE_BYTES
    ) {
        $opts = $options ?? new CacheOptions();
        $this->enabled = $opts->enabled && $opts->maxEntries > 0 && $opts->ttlSeconds > 0.0;
        $this->maxEntries = max(1, $opts->maxEntries);
        $this->ttlSeconds = max(0.001, $opts->ttlSeconds);
        $this->minFreeHeadroomBytes = $minFreeHeadroomBytes;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function get(string $key, ?float $nowEpochSeconds = null): ?IpLookupResponse
    {
        if (!$this->enabled) {
            return null;
        }

        if (!isset($this->store[$key])) {
            $this->misses++;
            return null;
        }

        $entry = $this->store[$key];
        $now = $nowEpochSeconds ?? microtime(true);
        if ($now >= $entry['expiresAt']) {
            unset($this->store[$key]);
            $this->misses++;
            return null;
        }

        // Promote to most-recently-used tail in O(1)
        unset($this->store[$key]);
        $this->store[$key] = $entry;
        $this->hits++;

        return $entry['value'];
    }

    public function set(string $key, IpLookupResponse $value, ?float $nowEpochSeconds = null): void
    {
        if (!$this->enabled) {
            return;
        }

        // Pre-OOM safety guard (CVE-2026-109618): skip caching if heap headroom is low
        try {
            IpScopeSecurity::assertMemoryHeadroom(2048, $this->minFreeHeadroomBytes);
        } catch (IpScopeMemoryLimitException) {
            return;
        }

        $now = $nowEpochSeconds ?? microtime(true);

        if (isset($this->store[$key])) {
            unset($this->store[$key]);
        } elseif (count($this->store) >= $this->maxEntries) {
            $oldestKey = array_key_first($this->store);
            if ($oldestKey !== null) {
                unset($this->store[$oldestKey]);
                $this->evictions++;
            }
        }

        $this->store[$key] = [
            'value' => $value,
            'expiresAt' => $now + $this->ttlSeconds,
        ];
    }

    public function clear(): void
    {
        $this->store = [];
        $this->hits = 0;
        $this->misses = 0;
        $this->evictions = 0;
    }

    public function stats(): CacheStats
    {
        return new CacheStats(
            enabled: $this->enabled,
            size: count($this->store),
            maxEntries: $this->maxEntries,
            hits: $this->hits,
            misses: $this->misses,
            evictions: $this->evictions,
        );
    }
}
