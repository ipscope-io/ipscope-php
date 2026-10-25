<?php

declare(strict_types=1);

namespace IpScope\Sdk;

/**
 * Security & Memory-Safety Guard mitigating CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)
 * and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp).
 *
 * Background:
 * - CVE-2026-109618: When PHP hits `memory_limit`, Zend Engine aborts via `longjmp()`
 *   (`zend_bailout`), which can leave partially initialized internal structures and cause
 *   memory corruption during request cleanup.
 * - CVE-2026-109619: Fatal/OOM bailouts in persistent workers (PHP-FPM, FrankenPHP,
 *   Swoole, RoadRunner) can leave stale internal state across subsequent requests.
 *
 * SDK Mitigations:
 * 1. Pre-Allocation Headroom Guard: Checks `memory_get_usage(true)` against `memory_limit`
 *    BEFORE buffering HTTP chunks or decoding JSON, throwing a catchable userland
 *    `IpScopeMemoryLimitException` before Zend Engine ever triggers an OOM `longjmp()`.
 * 2. Zero Static/Global State: The SDK uses zero mutable static properties or `$GLOBALS`.
 * 3. Runtime Patch Inspector: Detects whether the running PHP binary includes the official
 *    fixes (`>=8.2.35`, `>=8.3.36`, `>=8.4.27`, `>=8.5.12`).
 */
final class IpScopeSecurity
{
    /** Default minimum free PHP heap headroom (8 MiB) required before buffering responses. */
    public const DEFAULT_MIN_FREE_BYTES = 8 * 1024 * 1024;

    private function __construct() {}

    /**
     * Returns true if the current PHP runtime version includes the official fixes for
     * CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp).
     */
    public static function isPhpVersionPatched(int $versionId = PHP_VERSION_ID): bool
    {
        if ($versionId < 80200) {
            return false; // PHP 8.1 and older are EOL and unpatched
        }
        if ($versionId >= 80200 && $versionId < 80300) {
            return $versionId >= 80235; // Patched in 8.2.35
        }
        if ($versionId >= 80300 && $versionId < 80400) {
            return $versionId >= 80336; // Patched in 8.3.36
        }
        if ($versionId >= 80400 && $versionId < 80500) {
            return $versionId >= 80427; // Patched in 8.4.27
        }
        if ($versionId >= 80500 && $versionId < 80600) {
            return $versionId >= 80512; // Patched in 8.5.12
        }
        return true;
    }

    /**
     * Returns structured advisory metadata for the current PHP runtime.
     *
     * @return array{php_version: string, php_version_id: int, patched: bool, advisories: list<string>, recommendation: string}
     */
    public static function getRuntimeAdvisoryStatus(int $versionId = PHP_VERSION_ID, string $versionStr = PHP_VERSION): array
    {
        $patched = self::isPhpVersionPatched($versionId);
        return [
            'php_version' => $versionStr,
            'php_version_id' => $versionId,
            'patched' => $patched,
            'advisories' => ['CVE-2026-109618', 'CVE-2026-109619'],
            'recommendation' => $patched
                ? 'PHP runtime is patched against CVE-2026-109618 and CVE-2026-109619.'
                : 'Upgrade PHP immediately to >=8.2.35, >=8.3.36, >=8.4.27, or >=8.5.12 to patch CVE-2026-109618 and CVE-2026-109619.',
        ];
    }

    /**
     * Verifies that allocating `$additionalBytes` will keep at least `$minFreeHeadroomBytes`
     * below PHP's configured `memory_limit`. Throws a catchable `IpScopeMemoryLimitException`
     * in userland before Zend Engine can trigger a fatal OOM `longjmp()` (CVE-2026-109618).
     */
    public static function assertMemoryHeadroom(
        int $additionalBytes = 0,
        int $minFreeHeadroomBytes = self::DEFAULT_MIN_FREE_BYTES,
        ?int $overrideLimitBytes = null,
        ?int $overrideCurrentUsageBytes = null
    ): void {
        $limitBytes = $overrideLimitBytes ?? self::getPhpMemoryLimitBytes();
        if ($limitBytes <= 0) {
            return; // Unlimited (`memory_limit = -1`)
        }

        $currentUsage = $overrideCurrentUsageBytes ?? memory_get_usage(true);
        $projected = $currentUsage + max(0, $additionalBytes);
        $remaining = $limitBytes - $projected;

        if ($remaining < $minFreeHeadroomBytes) {
            throw new IpScopeMemoryLimitException(
                sprintf(
                    'IPScope pre-OOM safety guard aborted allocation (%d bytes requested, %d bytes used of %d bytes memory_limit) to prevent PHP fatal OOM bailout (CVE-2026-109618).',
                    $additionalBytes,
                    $currentUsage,
                    $limitBytes
                ),
                $currentUsage,
                $limitBytes
            );
        }
    }

    /**
     * Parses PHP's `memory_limit` INI directive into bytes, or returns -1 if unlimited.
     */
    public static function getPhpMemoryLimitBytes(?string $rawIniValue = null): int
    {
        $raw = $rawIniValue ?? (string) ini_get('memory_limit');
        $trimmed = trim($raw);
        if ($trimmed === '' || $trimmed === '-1') {
            return -1;
        }

        $unit = strtolower(substr($trimmed, -1));
        $numPart = is_numeric($unit) ? $trimmed : substr($trimmed, 0, -1);
        if (!is_numeric($numPart)) {
            return -1;
        }

        $bytes = (int) $numPart;
        return match ($unit) {
            'g' => $bytes * 1024 * 1024 * 1024,
            'm' => $bytes * 1024 * 1024,
            'k' => $bytes * 1024,
            default => $bytes,
        };
    }
}
