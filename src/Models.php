<?php

declare(strict_types=1);

namespace IpScope\Sdk;

/**
 * Lenient JSON value casting shared by the response models.
 *
 * @internal Not part of the public SDK API.
 */
final class ModelCast
{
    private function __construct() {}

    /** @param array<string, mixed> $raw */
    public static function str(array $raw, string $key): ?string
    {
        return isset($raw[$key]) && is_scalar($raw[$key]) ? (string) $raw[$key] : null;
    }

    /** @param array<string, mixed> $raw */
    public static function int(array $raw, string $key): ?int
    {
        return isset($raw[$key]) && is_numeric($raw[$key]) ? (int) $raw[$key] : null;
    }

    /** @param array<string, mixed> $raw */
    public static function float(array $raw, string $key): ?float
    {
        return isset($raw[$key]) && is_numeric($raw[$key]) ? (float) $raw[$key] : null;
    }

    /**
     * Numeric value kept as sent: an integer stays `int`, a fraction stays `float`.
     *
     * @param array<string, mixed> $raw
     */
    public static function number(array $raw, string $key): int|float|null
    {
        $v = $raw[$key] ?? null;
        if (is_int($v) || is_float($v)) {
            return $v;
        }
        return is_string($v) && is_numeric($v) ? $v + 0 : null;
    }

    /**
     * Tri-state boolean: `true`, `false`, or `null` when the API abstains or omits the field.
     *
     * @param array<string, mixed> $raw
     */
    public static function bool(array $raw, string $key): ?bool
    {
        return isset($raw[$key]) && is_bool($raw[$key]) ? $raw[$key] : null;
    }

    /**
     * @param array<string, mixed> $raw
     * @return array<string, mixed>|null
     */
    public static function obj(array $raw, string $key): ?array
    {
        return isset($raw[$key]) && is_array($raw[$key]) ? $raw[$key] : null;
    }

    /**
     * @param array<string, mixed> $raw
     * @return list<string>
     */
    public static function strList(array $raw, string $key): array
    {
        $out = [];
        if (isset($raw[$key]) && is_array($raw[$key])) {
            foreach ($raw[$key] as $item) {
                if (is_scalar($item)) {
                    $out[] = (string) $item;
                }
            }
        }
        return $out;
    }

    /**
     * Emits a deprecation notice for a 1.0 property alias and returns its value.
     */
    public static function deprecatedAlias(string $class, string $old, string $new, mixed $value): mixed
    {
        @trigger_error(
            sprintf('%s::$%s is deprecated since ipscope/ipscope-php 1.1.0; use $%s.', $class, $old, $new),
            E_USER_DEPRECATED
        );
        return $value;
    }

    /**
     * Mirrors PHP's own behaviour for an undefined property (warning, then null).
     */
    public static function undefined(string $class, string $name): mixed
    {
        trigger_error(sprintf('Undefined property: %s::$%s', $class, $name), E_USER_WARNING);
        return null;
    }
}

/**
 * Geographic block (`geo`) of a lookup response.
 */
final readonly class GeoBlock
{
    public function __construct(
        /** ISO-3166-1 alpha-2 country code, or null when abstaining. */
        public ?string $countryCode,
        /** ISO-3166-2 subdivision / region (code or name), or null. */
        public ?string $subdivision,
        public ?string $city,
        public ?string $postalCode,
        public ?float $latitude,
        public ?float $longitude,
        /** IANA timezone identifier, or null. */
        public ?string $timezone,
        /** `physical`, `declared`, `virtual`, `anycast`, or `unknown`. */
        public string $locationType,
        /** Calibrated confidence in [0.0, 1.0]. */
        public float $confidence,
        public ?float $accuracyRadiusKm,
        public ?string $declaredCountryCode,
        public ?string $physicalCountryCode,
        public ?bool $isVirtualLocation
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            countryCode: ModelCast::str($raw, 'country_code'),
            subdivision: ModelCast::str($raw, 'subdivision'),
            city: ModelCast::str($raw, 'city'),
            postalCode: ModelCast::str($raw, 'postal_code'),
            latitude: ModelCast::float($raw, 'latitude'),
            longitude: ModelCast::float($raw, 'longitude'),
            timezone: ModelCast::str($raw, 'timezone'),
            locationType: ModelCast::str($raw, 'location_type') ?? 'unknown',
            confidence: ModelCast::float($raw, 'confidence') ?? 0.0,
            accuracyRadiusKm: ModelCast::float($raw, 'accuracy_radius_km'),
            declaredCountryCode: ModelCast::str($raw, 'declared_country_code'),
            physicalCountryCode: ModelCast::str($raw, 'physical_country_code'),
            isVirtualLocation: ModelCast::bool($raw, 'is_virtual_location'),
        );
    }
}

/**
 * Autonomous System block (`network`) of a lookup response.
 *
 * @property-read ?string $org Deprecated 1.0 alias of `$organization`.
 */
final readonly class NetworkBlock
{
    public function __construct(
        public ?int $asn,
        /** Organization or AS holder name, or null. */
        public ?string $organization
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            asn: ModelCast::int($raw, 'asn'),
            organization: ModelCast::str($raw, 'organization'),
        );
    }

    public function __get(string $name): mixed
    {
        return match ($name) {
            'org' => ModelCast::deprecatedAlias(self::class, 'org', 'organization', $this->organization),
            default => ModelCast::undefined(self::class, $name),
        };
    }

    public function __isset(string $name): bool
    {
        return $name === 'org' && $this->organization !== null;
    }
}

/**
 * Security and anonymity block (`security`) of a lookup response.
 * Booleans are `null` when the API has insufficient evidence (never a silent `false`).
 *
 * @property-read ?bool $isTor Deprecated 1.0 alias of `$isTorExit`.
 * @property-read ?bool $isDatacenter Deprecated 1.0 alias of `$isHosting`.
 */
final readonly class SecurityBlock
{
    /**
     * @param list<string> $reasonCodes
     */
    public function __construct(
        public ?bool $isVpn,
        public ?bool $isHosting,
        public ?bool $isTorExit,
        public ?bool $isProxy,
        /** Consumer privacy relay egress (e.g. iCloud Private Relay); null/absent when unknown. */
        public ?bool $isRelay,
        /** `vpn`, `proxy`, `tor_exit`, `tor_relay`, `hosting_proxy`, `apple_private_relay`, `other_relay`, `none`, or `unknown`. */
        public string $anonymizerType,
        /** Calibrated confidence in [0.0, 1.0]. */
        public float $confidence,
        public array $reasonCodes
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            isVpn: ModelCast::bool($raw, 'is_vpn'),
            isHosting: ModelCast::bool($raw, 'is_hosting'),
            isTorExit: ModelCast::bool($raw, 'is_tor_exit'),
            isProxy: ModelCast::bool($raw, 'is_proxy'),
            isRelay: ModelCast::bool($raw, 'is_relay'),
            anonymizerType: ModelCast::str($raw, 'anonymizer_type') ?? 'unknown',
            confidence: ModelCast::float($raw, 'confidence') ?? 0.0,
            reasonCodes: ModelCast::strList($raw, 'reason_codes'),
        );
    }

    public function __get(string $name): mixed
    {
        return match ($name) {
            'isTor' => ModelCast::deprecatedAlias(self::class, 'isTor', 'isTorExit', $this->isTorExit),
            'isDatacenter' => ModelCast::deprecatedAlias(self::class, 'isDatacenter', 'isHosting', $this->isHosting),
            default => ModelCast::undefined(self::class, $name),
        };
    }

    public function __isset(string $name): bool
    {
        return match ($name) {
            'isTor' => $this->isTorExit !== null,
            'isDatacenter' => $this->isHosting !== null,
            default => false,
        };
    }
}

/**
 * Connection context block (`connection`), present only when the `connection` field family is licensed.
 */
final readonly class ConnectionBlock
{
    public function __construct(
        /** `residential`, `mobile`, `business`, `hosting`, `education`, `government`, or `unknown`. */
        public string $connectionType,
        public ?bool $isResidential,
        public ?bool $isMobile,
        public ?bool $isBusiness,
        public ?bool $isHosting
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            connectionType: ModelCast::str($raw, 'connection_type') ?? 'unknown',
            isResidential: ModelCast::bool($raw, 'is_residential'),
            isMobile: ModelCast::bool($raw, 'is_mobile'),
            isBusiness: ModelCast::bool($raw, 'is_business'),
            isHosting: ModelCast::bool($raw, 'is_hosting'),
        );
    }
}

/**
 * Security extensions block (`security_extensions`), present only when that field family is licensed.
 */
final readonly class SecurityExtensionsBlock
{
    public function __construct(
        /**
         * Abuse reputation / velocity score, or null. The API contract defines an integer
         * 0–100 (higher is worse); API releases before that change serve a fraction in
         * [0.0, 1.0]. The value is passed through unchanged, so check which form you got.
         */
        public int|float|null $abuseVelocityScore,
        public ?bool $isKnownScanner,
        /** Hours between the latest evidence observation and snapshot compilation, or null. */
        public ?float $observationRecencyHours
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            abuseVelocityScore: ModelCast::number($raw, 'abuse_velocity_score'),
            isKnownScanner: ModelCast::bool($raw, 'is_known_scanner'),
            observationRecencyHours: ModelCast::float($raw, 'observation_recency_hours'),
        );
    }
}

/**
 * Canonical IP lookup response (`GET /v1/ip/{ip}`, `GET /v1/ip/me`).
 *
 * @property-read int $version Deprecated 1.0 alias of `$ipVersion`.
 */
final readonly class IpLookupResponse
{
    public function __construct(
        public string $ip,
        /** 4 or 6. */
        public int $ipVersion,
        /** Most-specific matched CIDR prefix in the active snapshot, or null. */
        public ?string $matchedNetwork,
        public GeoBlock $geo,
        public NetworkBlock $network,
        public SecurityBlock $security,
        /** Null when the `connection` field family is not licensed (block omitted). */
        public ?ConnectionBlock $connection,
        /** Null when the `security_extensions` field family is not licensed (block omitted). */
        public ?SecurityExtensionsBlock $securityExtensions,
        /** Identifier of the serving dataset snapshot. */
        public string $datasetVersion,
        /** ISO-8601 timestamp of the most recent underlying evidence, or null. */
        public ?string $updatedAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $ip = ModelCast::str($raw, 'ip') ?? '';
        $connection = ModelCast::obj($raw, 'connection');
        $extensions = ModelCast::obj($raw, 'security_extensions');
        return new self(
            ip: $ip,
            ipVersion: ModelCast::int($raw, 'ip_version') ?? (str_contains($ip, ':') ? 6 : 4),
            matchedNetwork: ModelCast::str($raw, 'matched_network'),
            geo: GeoBlock::fromArray(ModelCast::obj($raw, 'geo') ?? []),
            network: NetworkBlock::fromArray(ModelCast::obj($raw, 'network') ?? []),
            security: SecurityBlock::fromArray(ModelCast::obj($raw, 'security') ?? []),
            connection: $connection !== null ? ConnectionBlock::fromArray($connection) : null,
            securityExtensions: $extensions !== null ? SecurityExtensionsBlock::fromArray($extensions) : null,
            datasetVersion: ModelCast::str($raw, 'dataset_version') ?? '',
            updatedAt: ModelCast::str($raw, 'updated_at'),
        );
    }

    public function __get(string $name): mixed
    {
        return match ($name) {
            'version' => ModelCast::deprecatedAlias(self::class, 'version', 'ipVersion', $this->ipVersion),
            default => ModelCast::undefined(self::class, $name),
        };
    }

    public function __isset(string $name): bool
    {
        return $name === 'version';
    }
}

/**
 * Batch IP lookup response (`POST /v1/ip/batch`).
 */
final readonly class BatchLookupResponse
{
    /**
     * @param list<IpLookupResponse> $results
     */
    public function __construct(
        public int $count,
        public array $results,
        /** Dataset snapshot all results are pinned to ('' if unknown). */
        public string $datasetVersion = ''
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $results = [];
        foreach (ModelCast::obj($raw, 'results') ?? [] as $item) {
            if (is_array($item)) {
                $results[] = IpLookupResponse::fromArray($item);
            }
        }

        return new self(
            count: ModelCast::int($raw, 'count') ?? count($results),
            results: $results,
            datasetVersion: ModelCast::str($raw, 'dataset_version') ?? '',
        );
    }
}

/**
 * A structured geographic assertion inside a canonical network record (camelCase on the wire).
 */
final readonly class LocationAssertion
{
    public function __construct(
        public ?string $countryCode,
        public ?string $countryName,
        public ?string $subdivision,
        public ?string $city,
        public ?float $latitude,
        public ?float $longitude,
        public ?float $accuracyRadiusKm,
        public ?string $timezone
    ) {}

    /** @param array<string, mixed>|null $raw */
    public static function fromNullableArray(?array $raw): ?self
    {
        if ($raw === null) {
            return null;
        }
        return new self(
            countryCode: ModelCast::str($raw, 'countryCode'),
            countryName: ModelCast::str($raw, 'countryName'),
            subdivision: ModelCast::str($raw, 'subdivision'),
            city: ModelCast::str($raw, 'city'),
            latitude: ModelCast::float($raw, 'latitude'),
            longitude: ModelCast::float($raw, 'longitude'),
            accuracyRadiusKm: ModelCast::float($raw, 'accuracyRadiusKm'),
            timezone: ModelCast::str($raw, 'timezone'),
        );
    }
}

/**
 * Declared, inferred-physical, and client locations kept separate in a canonical record.
 */
final readonly class SeparatedLocations
{
    public function __construct(
        public ?LocationAssertion $declaredLocation,
        public ?LocationAssertion $inferredPhysicalLocation,
        /** Always null for IP-only lookups. */
        public ?LocationAssertion $clientLocation
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            declaredLocation: LocationAssertion::fromNullableArray(ModelCast::obj($raw, 'declaredLocation')),
            inferredPhysicalLocation: LocationAssertion::fromNullableArray(ModelCast::obj($raw, 'inferredPhysicalLocation')),
            clientLocation: LocationAssertion::fromNullableArray(ModelCast::obj($raw, 'clientLocation')),
        );
    }
}

/**
 * Canonical network record stored in the serving snapshot (`record` of a network lookup).
 * The API serves this object with camelCase keys.
 */
final readonly class CanonicalNetworkPrefixRecord
{
    /**
     * @param list<string> $reasonCodes
     * @param list<string> $sourceIds
     * @param list<string> $licensePolicyIds
     */
    public function __construct(
        public int $family,
        public string $prefix,
        public ?int $asn,
        public ?string $organization,
        public SeparatedLocations $locations,
        public ?string $countryCode,
        public ?string $subdivision,
        public ?string $city,
        public ?string $postalCode,
        public ?float $latitude,
        public ?float $longitude,
        public ?string $timezone,
        public string $locationType,
        public float $geoConfidence,
        public ?float $accuracyRadiusKm,
        public ?bool $isVirtualLocation,
        public ?string $connectionType,
        public ?bool $isHosting,
        public ?bool $isVpn,
        public ?bool $isTorExit,
        public ?bool $isProxy,
        public string $anonymizerType,
        public float $securityConfidence,
        /** Integer 0–100 per the contract; older API releases serve a [0.0, 1.0] fraction. */
        public int|float|null $abuseVelocityScore,
        public ?bool $isKnownScanner,
        public array $reasonCodes,
        public array $sourceIds,
        public array $licensePolicyIds,
        public ?string $updatedAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $prefix = ModelCast::str($raw, 'prefix') ?? '';
        return new self(
            family: ModelCast::int($raw, 'family') ?? (str_contains($prefix, ':') ? 6 : 4),
            prefix: $prefix,
            asn: ModelCast::int($raw, 'asn'),
            organization: ModelCast::str($raw, 'organization'),
            locations: SeparatedLocations::fromArray(ModelCast::obj($raw, 'locations') ?? []),
            countryCode: ModelCast::str($raw, 'countryCode'),
            subdivision: ModelCast::str($raw, 'subdivision'),
            city: ModelCast::str($raw, 'city'),
            postalCode: ModelCast::str($raw, 'postalCode'),
            latitude: ModelCast::float($raw, 'latitude'),
            longitude: ModelCast::float($raw, 'longitude'),
            timezone: ModelCast::str($raw, 'timezone'),
            locationType: ModelCast::str($raw, 'locationType') ?? 'unknown',
            geoConfidence: ModelCast::float($raw, 'geoConfidence') ?? 0.0,
            accuracyRadiusKm: ModelCast::float($raw, 'accuracyRadiusKm'),
            isVirtualLocation: ModelCast::bool($raw, 'isVirtualLocation'),
            connectionType: ModelCast::str($raw, 'connectionType'),
            isHosting: ModelCast::bool($raw, 'isHosting'),
            isVpn: ModelCast::bool($raw, 'isVpn'),
            isTorExit: ModelCast::bool($raw, 'isTorExit'),
            isProxy: ModelCast::bool($raw, 'isProxy'),
            anonymizerType: ModelCast::str($raw, 'anonymizerType') ?? 'unknown',
            securityConfidence: ModelCast::float($raw, 'securityConfidence') ?? 0.0,
            abuseVelocityScore: ModelCast::number($raw, 'abuseVelocityScore'),
            isKnownScanner: ModelCast::bool($raw, 'isKnownScanner'),
            reasonCodes: ModelCast::strList($raw, 'reasonCodes'),
            sourceIds: ModelCast::strList($raw, 'sourceIds'),
            licensePolicyIds: ModelCast::strList($raw, 'licensePolicyIds'),
            updatedAt: ModelCast::str($raw, 'updatedAt'),
        );
    }
}

/**
 * Network CIDR lookup response (`GET /v1/networks/{address}/{prefixLength}`).
 */
final readonly class NetworkPrefixLookupResponse
{
    public function __construct(
        /** Canonical form of the CIDR that was queried. */
        public string $queriedCidr,
        /** Most-specific snapshot prefix covering the query. */
        public string $matchedNetwork,
        public int $family,
        public int $bgpPrefixLength,
        public string $datasetVersion,
        /** Canonical snapshot record, or null when no record covers the prefix. */
        public ?CanonicalNetworkPrefixRecord $record,
        /** Full IP lookup response for the prefix's base address. */
        public ?IpLookupResponse $lookup
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $queried = ModelCast::str($raw, 'queried_cidr') ?? '';
        $matched = ModelCast::str($raw, 'matched_network') ?? $queried;
        $record = ModelCast::obj($raw, 'record');
        $lookup = ModelCast::obj($raw, 'lookup');
        $slash = strrpos($matched, '/');
        return new self(
            queriedCidr: $queried,
            matchedNetwork: $matched,
            family: ModelCast::int($raw, 'family') ?? (str_contains($queried, ':') ? 6 : 4),
            bgpPrefixLength: ModelCast::int($raw, 'bgp_prefix_length')
                ?? ($slash !== false ? (int) substr($matched, $slash + 1) : 0),
            datasetVersion: ModelCast::str($raw, 'dataset_version') ?? '',
            record: $record !== null ? CanonicalNetworkPrefixRecord::fromArray($record) : null,
            lookup: $lookup !== null ? IpLookupResponse::fromArray($lookup) : null,
        );
    }
}

/**
 * Summary of one loaded dataset snapshot.
 */
final readonly class DatasetSnapshotSummary
{
    public function __construct(
        public string $snapshotVersion,
        public string $digest,
        public string $rulesetVersion,
        public string $publishedAt,
        public int $ipv4PrefixCount,
        public int $ipv6PrefixCount
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            snapshotVersion: ModelCast::str($raw, 'snapshot_version') ?? '',
            digest: ModelCast::str($raw, 'digest') ?? '',
            rulesetVersion: ModelCast::str($raw, 'ruleset_version') ?? '',
            publishedAt: ModelCast::str($raw, 'published_at') ?? '',
            ipv4PrefixCount: ModelCast::int($raw, 'ipv4_prefix_count') ?? 0,
            ipv6PrefixCount: ModelCast::int($raw, 'ipv6_prefix_count') ?? 0,
        );
    }
}

/**
 * Dataset snapshots metadata (`GET /v1/metadata/datasets`).
 */
final readonly class DatasetsMetadataResponse
{
    /**
     * @param list<DatasetSnapshotSummary> $snapshots
     */
    public function __construct(
        public string $activeVersion,
        public ?string $previousVersion,
        public array $snapshots
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $snapshots = [];
        foreach (ModelCast::obj($raw, 'snapshots') ?? [] as $item) {
            if (is_array($item)) {
                $snapshots[] = DatasetSnapshotSummary::fromArray($item);
            }
        }

        return new self(
            activeVersion: ModelCast::str($raw, 'active_version') ?? '',
            previousVersion: ModelCast::str($raw, 'previous_version'),
            snapshots: $snapshots,
        );
    }
}

/**
 * Correction report for `POST /v1/feedback`.
 */
final readonly class FeedbackSubmissionInput
{
    public const ROLES = ['network_owner', 'user', 'researcher'];

    public const ISSUE_TYPES = [
        'wrong_country',
        'wrong_city',
        'false_positive_vpn',
        'false_positive_hosting',
        'false_positive_tor',
        'virtual_location_mismatch',
        'other',
    ];

    /**
     * @param string $prefixOrIp Target IP address or CIDR prefix.
     * @param string $role One of {@see self::ROLES}.
     * @param string $issueType One of {@see self::ISSUE_TYPES}.
     * @param array<string, mixed> $requestedCorrection Requested corrected attributes, e.g. `['country_code' => 'DE']`.
     * @param string|null $evidenceUrl Optional public URL to geofeed / RDAP / traceroute evidence.
     */
    public function __construct(
        public string $prefixOrIp,
        public string $role,
        public string $issueType,
        public array $requestedCorrection = [],
        public ?string $evidenceUrl = null,
        public bool $contactConsent = false,
        public ?string $contactEmail = null
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $payload = [
            'prefix_or_ip' => $this->prefixOrIp,
            'role' => $this->role,
            'issue_type' => $this->issueType,
            // An empty PHP array would encode as `[]`; the API requires a JSON object.
            'requested_correction' => (object) $this->requestedCorrection,
            'contact_consent' => $this->contactConsent,
        ];
        if ($this->evidenceUrl !== null) {
            $payload['evidence_url'] = $this->evidenceUrl;
        }
        if ($this->contactEmail !== null) {
            $payload['contact_email'] = $this->contactEmail;
        }
        return $payload;
    }
}

/**
 * Feedback acknowledgment returned by `POST /v1/feedback`.
 */
final readonly class FeedbackSubmissionResponse
{
    /**
     * @param array<string, mixed> $requestedCorrection
     */
    public function __construct(
        public string $id,
        public string $prefixOrIp,
        public string $role,
        public string $issueType,
        public array $requestedCorrection,
        public ?string $evidenceUrl,
        public ?bool $contactConsent,
        public ?string $contactEmail,
        /** e.g. `pending_review`. */
        public string $status,
        public string $createdAt
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            id: ModelCast::str($raw, 'id') ?? '',
            prefixOrIp: ModelCast::str($raw, 'prefix_or_ip') ?? '',
            role: ModelCast::str($raw, 'role') ?? '',
            issueType: ModelCast::str($raw, 'issue_type') ?? '',
            requestedCorrection: ModelCast::obj($raw, 'requested_correction') ?? [],
            evidenceUrl: ModelCast::str($raw, 'evidence_url'),
            contactConsent: ModelCast::bool($raw, 'contact_consent'),
            contactEmail: ModelCast::str($raw, 'contact_email'),
            status: ModelCast::str($raw, 'status') ?? '',
            // The API returns camelCase `createdAt`; accept snake_case too.
            createdAt: ModelCast::str($raw, 'createdAt') ?? ModelCast::str($raw, 'created_at') ?? '',
        );
    }
}

/**
 * Serving and previous dataset versions reported by `GET /v1/status`.
 */
final readonly class ServiceSnapshotInfo
{
    public function __construct(
        public ?string $currentVersion,
        public ?string $previousVersion
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        return new self(
            currentVersion: ModelCast::str($raw, 'currentVersion'),
            previousVersion: ModelCast::str($raw, 'previousVersion'),
        );
    }
}

/**
 * Service health returned by `GET /v1/status`.
 */
final readonly class ServiceStatusResponse
{
    public function __construct(
        /** e.g. `healthy`. */
        public string $status,
        public ?ServiceSnapshotInfo $snapshot
    ) {}

    /** @param array<string, mixed> $raw */
    public static function fromArray(array $raw): self
    {
        $snapshot = ModelCast::obj($raw, 'snapshot');
        return new self(
            status: ModelCast::str($raw, 'status') ?? '',
            snapshot: $snapshot !== null ? ServiceSnapshotInfo::fromArray($snapshot) : null,
        );
    }

    /** Dataset version currently served (the `dataset_version` lookups return). */
    public function currentVersion(): ?string
    {
        return $this->snapshot?->currentVersion;
    }

    public function previousVersion(): ?string
    {
        return $this->snapshot?->previousVersion;
    }
}

/**
 * Rate-limit metadata from the `X-RateLimit-*` response headers. Limits apply per user, not per key.
 */
final readonly class RateLimitMetadata
{
    /**
     * @deprecated since 1.1.0. Misnamed in 1.0: the API sends seconds until the window
     *             resets, not an epoch timestamp. Holds the same value as `$resetAfterSeconds`.
     */
    public ?int $resetEpochSeconds;

    /** @deprecated since 1.1.0. The API never sends a credits header; always null. */
    public ?int $creditsRemaining;

    /** @deprecated since 1.1.0. The API never sends a tier header; always null. */
    public ?string $planTier;

    public function __construct(
        /** Requests allowed per window (`X-RateLimit-Limit`). */
        public ?int $limit = null,
        /** Requests left in the current window (`X-RateLimit-Remaining`). */
        public ?int $remaining = null,
        /** Seconds until the window resets (`X-RateLimit-Reset`). */
        public ?int $resetAfterSeconds = null,
        /** What the limit applies to, e.g. `user` (`X-RateLimit-Scope`). */
        public ?string $scope = null
    ) {
        $this->resetEpochSeconds = $resetAfterSeconds;
        $this->creditsRemaining = null;
        $this->planTier = null;
    }
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
