# Changelog

All notable changes to `ipscope/ipscope-php` are documented here.
The project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-10

1.0.0 did not match the live IPScope API. Several methods called URLs that do not
exist, and the response models were built around field names the API never sends,
so most fields came back as `null`/`false` even when the request worked. 1.1.0 fixes
the SDK against the real API at `https://api.ipscope.io`.

### Fixed

- **Endpoint paths** (each returned HTTP 404 in 1.0.0):
  - `lookupCallerIp()` now calls `GET /v1/ip/me` (was `GET /v1/ip`).
  - `lookupNetwork()` now calls `GET /v1/networks/{address}/{length}` (was `/v1/network/...`).
  - `getDatasetsMetadata()` now calls `GET /v1/metadata/datasets` (was `/v1/datasets/metadata`).
- **Response models rebuilt from the API's response contract.**
  - `IpLookupResponse`: `ipVersion`, `matchedNetwork`, `datasetVersion`, and `updatedAt` (nullable).
  - `GeoBlock`: `countryCode`, `subdivision`, `city`, `postalCode`, `latitude`, `longitude`,
    `timezone`, `locationType`, `confidence`, `accuracyRadiusKm`, `declaredCountryCode`,
    `physicalCountryCode`, `isVirtualLocation`.
  - `NetworkBlock`: `asn`, `organization`.
  - `SecurityBlock`: `isVpn`, `isHosting`, `isTorExit`, `isProxy`, `isRelay`, `anonymizerType`,
    `confidence`, `reasonCodes`. The booleans are now `?bool`: `null` means the API did not
    have enough evidence, which is different from `false`.
  - `ConnectionBlock`: `connectionType`, `isResidential`, `isMobile`, `isBusiness`, `isHosting`.
  - `SecurityExtensionsBlock`: `abuseVelocityScore`, `isKnownScanner`, `observationRecencyHours`.
    `abuseVelocityScore` is `int|float|null` and is passed through unchanged. The API contract
    defines it as an integer 0–100 (higher is worse). API releases from before that change
    serve a fraction in 0.0–1.0, so code written against both should check which form it got.
  - `connection` and `securityExtensions` are `null` when your plan does not license those
    field families (the API leaves those blocks out).
  - `BatchLookupResponse` gains `datasetVersion`.
  - `NetworkPrefixLookupResponse` is now `queriedCidr`, `matchedNetwork`, `family`,
    `bgpPrefixLength`, `datasetVersion`, `record` (a `CanonicalNetworkPrefixRecord` with the
    snapshot's own fields, or `null`), and `lookup` (a full `IpLookupResponse`). New supporting
    classes: `SeparatedLocations`, `LocationAssertion`.
  - `DatasetsMetadataResponse` is now `activeVersion`, `previousVersion`, `snapshots[]`
    (`snapshotVersion`, `digest`, `rulesetVersion`, `publishedAt`, `ipv4PrefixCount`, `ipv6PrefixCount`).
  - `ServiceStatusResponse` is now `status` plus `snapshot` (`ServiceSnapshotInfo` with
    `currentVersion`/`previousVersion`), with `currentVersion()`/`previousVersion()` helpers.
- **`submitFeedback()` sends the body the API accepts:** `prefix_or_ip`, `role`
  (`network_owner`|`user`|`researcher`), `issue_type` (`wrong_country`|`wrong_city`|
  `false_positive_vpn`|`false_positive_hosting`|`false_positive_tor`|`virtual_location_mismatch`|`other`),
  `requested_correction` (object), and optionally `evidence_url`, `contact_consent`, `contact_email`.
  The SDK checks role, issue type, URL, and email before sending the request. `FeedbackSubmissionResponse`
  reads the API's `createdAt` (and still accepts `created_at`).
- **Rate-limit headers:** the SDK now parses `X-RateLimit-Limit`, `-Remaining`, `-Reset`, and `-Scope`.
  `X-RateLimit-Reset` is the number of **seconds until the window resets**, exposed as
  `RateLimitMetadata::$resetAfterSeconds`; `$scope` is new (e.g. `user`). The SDK no longer
  parses `X-RateLimit-Credits-Remaining` or `X-RateLimit-Tier`, which the API never sends.
- **User-Agent** now reports `ipscope-sdk-php/1.1.0` (1.0.0 sent `0.1.0`). The version lives in
  one constant, `HttpTransport::SDK_VERSION`, also available as `IpScopeClient::VERSION`.
- The README examples now use the real API fields.

### Deprecated

These still work in 1.1.x and will be removed in 2.0. Reading one of the property aliases
raises an `E_USER_DEPRECATED` notice.

- `RateLimitMetadata::$resetEpochSeconds`: the name was wrong. It holds the **same seconds-until-reset
  value** as `$resetAfterSeconds`, not an epoch timestamp. Use `$resetAfterSeconds`.
- `RateLimitMetadata::$creditsRemaining`, `RateLimitMetadata::$planTier`: always `null` (no such headers).
- `NetworkBlock::$org` → `$organization`.
- `SecurityBlock::$isTor` → `$isTorExit`; `SecurityBlock::$isDatacenter` → `$isHosting`.
- `IpLookupResponse::$version` → `$ipVersion`.

### Breaking changes

- `FeedbackSubmissionInput` now has the API's fields (`prefixOrIp`, `role`, `issueType`,
  `requestedCorrection`, `evidenceUrl`, `contactConsent`, `contactEmail`). The 1.0 fields
  (`ipOrCidr`, `suggested*`, `notes`) are gone. The API rejected every 1.0 submission, so no
  working code depended on them.
- 1.0 model properties that the API never sends have been removed: for example `threatLevel`,
  `threatTypes`, `asnName`, `isp`, `bgpPrefix`, `rir`, `isBogon`, `countryName`, `regionCode`,
  the old `ConnectionBlock`/`SecurityExtensionsBlock` fields, and the old network, datasets,
  and status response fields. In 1.0 they were always `null`/`false`/empty. Reading one now
  raises PHP's usual "Undefined property" warning and returns `null`.
- The network, datasets, and caller-IP response models changed shape. In 1.0 those methods
  always failed with HTTP 404.
