<?php

declare(strict_types=1);

namespace IpScope\Sdk;

/**
 * Zero-DNS client-side validator for IP addresses, CIDR prefixes, and API keys.
 */
final class IpScopeValidator
{
    public const MAX_BATCH_SIZE = 100;

    private function __construct() {}

    public static function validateApiKey(string $apiKey): string
    {
        $trimmed = trim($apiKey);
        if ($trimmed === '' || strlen($trimmed) < 8) {
            throw new IpScopeValidationException(
                'A valid IPScope API key ("<public>:<private>") is required.',
                'apiKey'
            );
        }
        return $trimmed;
    }

    /**
     * Validates and canonicalizes an IPv4 or IPv6 literal without performing DNS resolution.
     */
    public static function validateIpAddress(string $ip, string $fieldName = 'ip'): string
    {
        $trimmed = trim($ip);
        if ($trimmed === '') {
            throw new IpScopeValidationException('IP address must be a non-empty string.', $fieldName);
        }

        // Strip optional IPv6 zone identifier (%eth0)
        $percentPos = strpos($trimmed, '%');
        $clean = $percentPos !== false ? substr($trimmed, 0, $percentPos) : $trimmed;

        if (filter_var($clean, FILTER_VALIDATE_IP) === false) {
            throw new IpScopeValidationException(
                sprintf('Invalid IPv4 or IPv6 address: "%s".', $trimmed),
                $fieldName
            );
        }

        $packed = @inet_pton($clean);
        if ($packed === false) {
            throw new IpScopeValidationException(
                sprintf('Invalid IPv4 or IPv6 address: "%s".', $trimmed),
                $fieldName
            );
        }

        $canonical = @inet_ntop($packed);
        return $canonical !== false ? $canonical : strtolower($clean);
    }

    /**
     * Validates and normalizes a CIDR prefix (`8.8.8.0/24` or `2001:4860::/32`).
     *
     * @return array{address: string, prefixLength: int, canonicalCidr: string}
     */
    public static function validateCidrPrefix(string $cidr): array
    {
        $trimmed = trim($cidr);
        $slashPos = strpos($trimmed, '/');
        if ($slashPos === false || strpos($trimmed, '/', $slashPos + 1) !== false) {
            throw new IpScopeValidationException(
                sprintf('Invalid CIDR notation "%s". Expected "<ip>/<prefixLength>" (e.g. "8.8.8.0/24").', $cidr),
                'cidr'
            );
        }

        $rawAddress = trim(substr($trimmed, 0, $slashPos));
        $rawPrefix = trim(substr($trimmed, $slashPos + 1));

        if ($rawPrefix === '' || !ctype_digit($rawPrefix)) {
            throw new IpScopeValidationException(
                sprintf('Invalid prefix length in CIDR "%s".', $cidr),
                'cidr'
            );
        }

        if (filter_var($rawAddress, FILTER_VALIDATE_IP) === false) {
            throw new IpScopeValidationException(
                sprintf('Invalid network IP address in CIDR "%s".', $cidr),
                'cidr'
            );
        }

        $packed = @inet_pton($rawAddress);
        if ($packed === false) {
            throw new IpScopeValidationException(
                sprintf('Invalid network IP address in CIDR "%s".', $cidr),
                'cidr'
            );
        }

        $prefixLen = (int) $rawPrefix;
        $maxBits = strlen($packed) === 4 ? 32 : 128;
        if ($prefixLen < 0 || $prefixLen > $maxBits) {
            throw new IpScopeValidationException(
                sprintf('Prefix length %d is out of range (0..%d) for "%s".', $prefixLen, $maxBits, $cidr),
                'cidr'
            );
        }

        // Mask host bits to obtain the canonical network address
        $bytes = array_values(unpack('C*', $packed) ?: []);
        $fullBytes = intdiv($prefixLen, 8);
        $remBits = $prefixLen % 8;

        $maskedBytes = [];
        $totalBytes = count($bytes);
        for ($i = 0; $i < $totalBytes; $i++) {
            if ($i < $fullBytes) {
                $maskedBytes[] = $bytes[$i];
            } elseif ($i === $fullBytes && $remBits > 0) {
                $mask = (0xFF << (8 - $remBits)) & 0xFF;
                $maskedBytes[] = $bytes[$i] & $mask;
            } else {
                $maskedBytes[] = 0;
            }
        }

        $maskedPacked = pack('C*', ...$maskedBytes);
        $networkAddr = @inet_ntop($maskedPacked);
        if ($networkAddr === false) {
            $networkAddr = $rawAddress;
        }

        return [
            'address' => $networkAddr,
            'prefixLength' => $prefixLen,
            'canonicalCidr' => sprintf('%s/%d', $networkAddr, $prefixLen),
        ];
    }

    /**
     * Validates and deduplicates a batch of IP addresses (1..100 items by default).
     *
     * @param list<string> $ips
     * @return list<string>
     */
    public static function validateAndDeduplicateBatchIps(array $ips, int $maxSize = self::MAX_BATCH_SIZE): array
    {
        if ($ips === []) {
            throw new IpScopeValidationException(
                'Batch IP list must contain at least 1 IP address.',
                'ips'
            );
        }

        $unique = [];
        $seen = [];
        foreach (array_values($ips) as $idx => $raw) {
            if (!is_string($raw)) {
                throw new IpScopeValidationException(
                    sprintf('Expected string at ips[%d].', $idx),
                    sprintf('ips[%d]', $idx)
                );
            }
            $canonical = self::validateIpAddress($raw, sprintf('ips[%d]', $idx));
            if (!isset($seen[$canonical])) {
                $seen[$canonical] = true;
                $unique[] = $canonical;
            }
        }

        if (count($unique) > $maxSize) {
            throw new IpScopeValidationException(
                sprintf(
                    'Batch IP list exceeds maximum of %d unique IPs (%d provided). Use lookupBatchChunked() or lookupBatchStream() for larger lists.',
                    $maxSize,
                    count($unique)
                ),
                'ips'
            );
        }

        return $unique;
    }
}
