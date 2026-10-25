<?php

declare(strict_types=1);

namespace IpScope\Sdk;

/**
 * Geographic location intelligence block.
 */
final readonly class GeoBlock
{
    public function __construct(
        public ?string $countryCode,
        public ?string $countryName,
        public ?string $regionCode,
        public ?string $regionName,
        public ?string $city,
        public ?string $postalCode,
        public ?float $latitude,
        public ?float $longitude,
        public ?string $timezone,
        public ?int $accuracyRadiusKm
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            countryCode: isset($raw['country_code']) ? (string) $raw['country_code'] : null,
            countryName: isset($raw['country_name']) ? (string) $raw['country_name'] : null,
            regionCode: isset($raw['region_code']) ? (string) $raw['region_code'] : null,
            regionName: isset($raw['region_name']) ? (string) $raw['region_name'] : null,
            city: isset($raw['city']) ? (string) $raw['city'] : null,
            postalCode: isset($raw['postal_code']) ? (string) $raw['postal_code'] : null,
            latitude: isset($raw['latitude']) ? (float) $raw['latitude'] : null,
            longitude: isset($raw['longitude']) ? (float) $raw['longitude'] : null,
            timezone: isset($raw['timezone']) ? (string) $raw['timezone'] : null,
            accuracyRadiusKm: isset($raw['accuracy_radius_km']) ? (int) $raw['accuracy_radius_km'] : null,
        );
    }
}

/**
 * Autonomous System (ASN) and BGP prefix block.
 */
final readonly class NetworkBlock
{
    public function __construct(
        public ?int $asn,
        public ?string $asnName,
        public ?string $org,
        public ?string $isp,
        public ?string $connectionType,
        public ?string $bgpPrefix,
        public ?string $rir
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            asn: isset($raw['asn']) ? (int) $raw['asn'] : null,
            asnName: isset($raw['asn_name']) ? (string) $raw['asn_name'] : null,
            org: isset($raw['org']) ? (string) $raw['org'] : null,
            isp: isset($raw['isp']) ? (string) $raw['isp'] : null,
            connectionType: isset($raw['connection_type']) ? (string) $raw['connection_type'] : null,
            bgpPrefix: isset($raw['bgp_prefix']) ? (string) $raw['bgp_prefix'] : null,
            rir: isset($raw['rir']) ? (string) $raw['rir'] : null,
        );
    }
}

/**
 * Anonymity, proxy, VPN, Tor, and threat intelligence block.
 */
final readonly class SecurityBlock
{
    /**
     * @param list<string> $threatTypes
     */
    public function __construct(
        public bool $isVpn,
        public bool $isProxy,
        public bool $isTor,
        public bool $isDatacenter,
        public bool $isRelay,
        public string $threatLevel,
        public array $threatTypes
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $rawTypes = isset($raw['threat_types']) && is_array($raw['threat_types'])
            ? $raw['threat_types']
            : [];
        $types = [];
        foreach ($rawTypes as $item) {
            if (is_scalar($item)) {
                $types[] = (string) $item;
            }
        }

        return new self(
            isVpn: (bool) ($raw['is_vpn'] ?? false),
            isProxy: (bool) ($raw['is_proxy'] ?? false),
            isTor: (bool) ($raw['is_tor'] ?? false),
            isDatacenter: (bool) ($raw['is_datacenter'] ?? false),
            isRelay: (bool) ($raw['is_relay'] ?? false),
            threatLevel: isset($raw['threat_level']) ? (string) $raw['threat_level'] : 'low',
            threatTypes: $types,
        );
    }
}

/**
 * Detailed connection and carrier classification block.
 */
final readonly class ConnectionBlock
{
    public function __construct(
        public ?string $usageType,
        public ?string $companyType,
        public ?string $carrierName,
        public ?string $mcc,
        public ?string $mnc,
        public ?string $domain,
        public ?string $route,
        public ?string $allocatedDate,
        public ?string $registryStatus
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            usageType: isset($raw['usage_type']) ? (string) $raw['usage_type'] : null,
            companyType: isset($raw['company_type']) ? (string) $raw['company_type'] : null,
            carrierName: isset($raw['carrier_name']) ? (string) $raw['carrier_name'] : null,
            mcc: isset($raw['mcc']) ? (string) $raw['mcc'] : null,
            mnc: isset($raw['mnc']) ? (string) $raw['mnc'] : null,
            domain: isset($raw['domain']) ? (string) $raw['domain'] : null,
            route: isset($raw['route']) ? (string) $raw['route'] : null,
            allocatedDate: isset($raw['allocated_date']) ? (string) $raw['allocated_date'] : null,
            registryStatus: isset($raw['registry_status']) ? (string) $raw['registry_status'] : null,
        );
    }
}

/**
 * Extended threat scoring and provider attribution block.
 */
final readonly class SecurityExtensionsBlock
{
    public function __construct(
        public ?string $vpnProvider,
        public ?string $proxyType,
        public ?int $threatScore,
        public bool $isAbuser,
        public bool $isBot,
        public bool $isBogon
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            vpnProvider: isset($raw['vpn_provider']) ? (string) $raw['vpn_provider'] : null,
            proxyType: isset($raw['proxy_type']) ? (string) $raw['proxy_type'] : null,
            threatScore: isset($raw['threat_score']) ? (int) $raw['threat_score'] : null,
            isAbuser: (bool) ($raw['is_abuser'] ?? false),
            isBot: (bool) ($raw['is_bot'] ?? false),
            isBogon: (bool) ($raw['is_bogon'] ?? false),
        );
    }
}

/**
 * Canonical IP intelligence response returned by `/v1/ip` and `/v1/ip/{ip}`.
 */
final readonly class IpLookupResponse
{
    public function __construct(
        public string $ip,
        public int $version,
        public bool $isBogon,
        public ?string $bogonType,
        public GeoBlock $geo,
        public NetworkBlock $network,
        public SecurityBlock $security,
        public ?ConnectionBlock $connection,
        public ?SecurityExtensionsBlock $securityExtensions,
        public string $updatedAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            ip: isset($raw['ip']) ? (string) $raw['ip'] : '',
            version: isset($raw['version']) ? (int) $raw['version'] : 4,
            isBogon: (bool) ($raw['is_bogon'] ?? false),
            bogonType: isset($raw['bogon_type']) ? (string) $raw['bogon_type'] : null,
            geo: GeoBlock::fromArray(isset($raw['geo']) && is_array($raw['geo']) ? $raw['geo'] : []),
            network: NetworkBlock::fromArray(isset($raw['network']) && is_array($raw['network']) ? $raw['network'] : []),
            security: SecurityBlock::fromArray(isset($raw['security']) && is_array($raw['security']) ? $raw['security'] : []),
            connection: isset($raw['connection']) && is_array($raw['connection'])
                ? ConnectionBlock::fromArray($raw['connection'])
                : null,
            securityExtensions: isset($raw['security_extensions']) && is_array($raw['security_extensions'])
                ? SecurityExtensionsBlock::fromArray($raw['security_extensions'])
                : null,
            updatedAt: isset($raw['updated_at']) ? (string) $raw['updated_at'] : '',
        );
    }
}

/**
 * Batch IP lookup response returned by `POST /v1/ip/batch`.
 */
final readonly class BatchLookupResponse
{
    /**
     * @param list<IpLookupResponse> $results
     */
    public function __construct(
        public int $count,
        public array $results
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $rawList = isset($raw['results']) && is_array($raw['results']) ? $raw['results'] : [];
        $results = [];
        foreach ($rawList as $item) {
            if (is_array($item)) {
                $results[] = IpLookupResponse::fromArray($item);
            }
        }

        return new self(
            count: isset($raw['count']) ? (int) $raw['count'] : count($results),
            results: $results,
        );
    }
}

/**
 * Canonical BGP/CIDR prefix intelligence record.
 */
final readonly class CanonicalNetworkPrefixRecord
{
    public function __construct(
        public string $networkCidr,
        public int $ipVersion,
        public GeoBlock $geo,
        public NetworkBlock $network,
        public SecurityBlock $security,
        public ?ConnectionBlock $connection,
        public ?SecurityExtensionsBlock $securityExtensions,
        public string $updatedAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            networkCidr: isset($raw['network_cidr']) ? (string) $raw['network_cidr'] : '',
            ipVersion: isset($raw['ip_version']) ? (int) $raw['ip_version'] : 4,
            geo: GeoBlock::fromArray(isset($raw['geo']) && is_array($raw['geo']) ? $raw['geo'] : []),
            network: NetworkBlock::fromArray(isset($raw['network']) && is_array($raw['network']) ? $raw['network'] : []),
            security: SecurityBlock::fromArray(isset($raw['security']) && is_array($raw['security']) ? $raw['security'] : []),
            connection: isset($raw['connection']) && is_array($raw['connection'])
                ? ConnectionBlock::fromArray($raw['connection'])
                : null,
            securityExtensions: isset($raw['security_extensions']) && is_array($raw['security_extensions'])
                ? SecurityExtensionsBlock::fromArray($raw['security_extensions'])
                : null,
            updatedAt: isset($raw['updated_at']) ? (string) $raw['updated_at'] : '',
        );
    }
}

/**
 * Network CIDR lookup response returned by `GET /v1/network/{address}/{prefixLength}`.
 */
final readonly class NetworkPrefixLookupResponse
{
    /**
     * @param list<CanonicalNetworkPrefixRecord> $overlappingPrefixes
     */
    public function __construct(
        public string $requestedCidr,
        public ?CanonicalNetworkPrefixRecord $exactMatch,
        public ?CanonicalNetworkPrefixRecord $enclosingPrefix,
        public array $overlappingPrefixes,
        public int $totalMatches
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $rawOverlaps = isset($raw['overlapping_prefixes']) && is_array($raw['overlapping_prefixes'])
            ? $raw['overlapping_prefixes']
            : [];
        $overlaps = [];
        foreach ($rawOverlaps as $item) {
            if (is_array($item)) {
                $overlaps[] = CanonicalNetworkPrefixRecord::fromArray($item);
            }
        }

        return new self(
            requestedCidr: isset($raw['requested_cidr']) ? (string) $raw['requested_cidr'] : '',
            exactMatch: isset($raw['exact_match']) && is_array($raw['exact_match'])
                ? CanonicalNetworkPrefixRecord::fromArray($raw['exact_match'])
                : null,
            enclosingPrefix: isset($raw['enclosing_prefix']) && is_array($raw['enclosing_prefix'])
                ? CanonicalNetworkPrefixRecord::fromArray($raw['enclosing_prefix'])
                : null,
            overlappingPrefixes: $overlaps,
            totalMatches: isset($raw['total_matches']) ? (int) $raw['total_matches'] : count($overlaps),
        );
    }
}

/**
 * Snapshot metadata for a single IP intelligence dataset source.
 */
final readonly class DatasetSnapshotSummary
{
    public function __construct(
        public string $source,
        public string $versionTag,
        public string $checksumSha256,
        public int $recordCount,
        public ?string $activatedAt,
        public string $createdAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            source: isset($raw['source']) ? (string) $raw['source'] : '',
            versionTag: isset($raw['version_tag']) ? (string) $raw['version_tag'] : '',
            checksumSha256: isset($raw['checksum_sha256']) ? (string) $raw['checksum_sha256'] : '',
            recordCount: isset($raw['record_count']) ? (int) $raw['record_count'] : 0,
            activatedAt: isset($raw['activated_at']) ? (string) $raw['activated_at'] : null,
            createdAt: isset($raw['created_at']) ? (string) $raw['created_at'] : '',
        );
    }
}

/**
 * Active dataset snapshots metadata returned by `GET /v1/datasets/metadata`.
 */
final readonly class DatasetsMetadataResponse
{
    /**
     * @param list<DatasetSnapshotSummary> $activeDatasets
     */
    public function __construct(
        public int $count,
        public array $activeDatasets
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $rawList = isset($raw['active_datasets']) && is_array($raw['active_datasets'])
            ? $raw['active_datasets']
            : [];
        $datasets = [];
        foreach ($rawList as $item) {
            if (is_array($item)) {
                $datasets[] = DatasetSnapshotSummary::fromArray($item);
            }
        }

        return new self(
            count: isset($raw['count']) ? (int) $raw['count'] : count($datasets),
            activeDatasets: $datasets,
        );
    }
}

/**
 * Payload for submitting an IP geolocation or anonymity correction (`POST /v1/feedback`).
 */
final readonly class FeedbackSubmissionInput
{
    public function __construct(
        public string $ipOrCidr,
        public ?string $suggestedCountryCode = null,
        public ?string $suggestedRegionName = null,
        public ?string $suggestedCity = null,
        public ?bool $suggestedIsVpn = null,
        public ?string $notes = null,
        public ?string $contactEmail = null
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $payload = ['ip_or_cidr' => $this->ipOrCidr];
        if ($this->suggestedCountryCode !== null) {
            $payload['suggested_country_code'] = $this->suggestedCountryCode;
        }
        if ($this->suggestedRegionName !== null) {
            $payload['suggested_region_name'] = $this->suggestedRegionName;
        }
        if ($this->suggestedCity !== null) {
            $payload['suggested_city'] = $this->suggestedCity;
        }
        if ($this->suggestedIsVpn !== null) {
            $payload['suggested_is_vpn'] = $this->suggestedIsVpn;
        }
        if ($this->notes !== null) {
            $payload['notes'] = $this->notes;
        }
        if ($this->contactEmail !== null) {
            $payload['contact_email'] = $this->contactEmail;
        }
        return $payload;
    }
}

/**
 * Feedback submission acknowledgment returned by `POST /v1/feedback`.
 */
final readonly class FeedbackSubmissionResponse
{
    public function __construct(
        public string $id,
        public string $ipOrCidr,
        public string $status,
        public string $createdAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            id: isset($raw['id']) ? (string) $raw['id'] : '',
            ipOrCidr: isset($raw['ip_or_cidr']) ? (string) $raw['ip_or_cidr'] : '',
            status: isset($raw['status']) ? (string) $raw['status'] : '',
            createdAt: isset($raw['created_at']) ? (string) $raw['created_at'] : '',
        );
    }
}

/**
 * Service health status returned by `GET /v1/status`.
 */
final readonly class ServiceStatusResponse
{
    public function __construct(
        public string $status,
        public string $service,
        public string $version,
        public float $uptimeSeconds,
        public string $timestamp
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            status: isset($raw['status']) ? (string) $raw['status'] : '',
            service: isset($raw['service']) ? (string) $raw['service'] : '',
            version: isset($raw['version']) ? (string) $raw['version'] : '',
            uptimeSeconds: isset($raw['uptime_seconds']) ? (float) $raw['uptime_seconds'] : 0.0,
            timestamp: isset($raw['timestamp']) ? (string) $raw['timestamp'] : '',
        );
    }
}

/**
 * Rate-limit and quota metadata extracted from `x-ratelimit-*` HTTP response headers.
 */
final readonly class RateLimitMetadata
{
    public function __construct(
        public ?int $limit = null,
        public ?int $remaining = null,
        public ?int $resetEpochSeconds = null,
        public ?int $creditsRemaining = null,
        public ?string $planTier = null
    ) {}
}

/**
 * Wrapper pairing a response payload with rate-limit metadata and cache hit status.
 */
final readonly class IpScopeResultWithMeta
{
    public function __construct(
        public IpLookupResponse $data,
        public ?RateLimitMetadata $rateLimit,
        public bool $fromCache
    ) {}
}

/**
 * Snapshot of in-memory LRU cache statistics.
 */
final readonly class CacheStats
{
    public function __construct(
        public bool $enabled,
        public int $size,
        public int $maxEntries,
        public int $hits,
        public int $misses,
        public int $evictions
    ) {}
}

/**
 * Retry configuration for transient HTTP errors (`429`, `502`, `503`, `504`).
 */
final readonly class RetryOptions
{
    public function __construct(
        public int $maxRetries = 2,
        public float $initialDelaySeconds = 0.25,
        public float $maxDelaySeconds = 4.0
    ) {}
}

/**
 * Bounded LRU + TTL cache configuration (`maxEntries = 512` default `< 400 KB`).
 */
final readonly class CacheOptions
{
    public function __construct(
        public bool $enabled = true,
        public int $maxEntries = 512,
        public float $ttlSeconds = 60.0
    ) {}
}

/**
 * Per-request options.
 */
final readonly class RequestOptions
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public bool $bypassCache = false,
        public ?float $timeoutSeconds = null,
        public array $headers = []
    ) {}
}
