<?php

declare(strict_types=1);

namespace IpScope\Sdk;

use RuntimeException;
use Throwable;

/**
 * Base exception for all errors thrown by the IPScope PHP SDK.
 */
class IpScopeException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $errorCode = 'IPSCOPE_ERROR',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}

/**
 * Thrown when client-side validation fails before making an HTTP request.
 */
final class IpScopeValidationException extends IpScopeException
{
    public function __construct(
        string $message,
        public readonly ?string $field = null
    ) {
        parent::__construct($message, 'IPSCOPE_VALIDATION_ERROR');
    }
}

/**
 * Thrown when an HTTP request exceeds the configured timeout.
 */
final class IpScopeTimeoutException extends IpScopeException
{
    public function __construct(
        public readonly string $path,
        public readonly float $timeoutSeconds,
        ?Throwable $previous = null
    ) {
        parent::__construct(
            sprintf('IPScope request to "%s" timed out after %.2fs', $path, $timeoutSeconds),
            'IPSCOPE_TIMEOUT_ERROR',
            0,
            $previous
        );
    }
}

/**
 * Thrown when the pre-OOM memory safety guard detects insufficient heap headroom
 * before Zend Engine's `memory_limit` fatal bailout (CVE-2026-109618) can trigger.
 */
final class IpScopeMemoryLimitException extends IpScopeException
{
    public function __construct(
        string $message,
        public readonly int $currentUsageBytes,
        public readonly int $memoryLimitBytes
    ) {
        parent::__construct($message, 'IPSCOPE_MEMORY_LIMIT_GUARD');
    }
}

/**
 * Thrown when the IPScope API returns a non-2xx HTTP status code or transport error.
 */
class IpScopeApiException extends IpScopeException
{
    public function __construct(
        string $message,
        public readonly int $status,
        public readonly string $path,
        ?string $errorCode = null,
        public readonly ?RateLimitMetadata $rateLimit = null,
        ?Throwable $previous = null
    ) {
        parent::__construct(
            $message,
            $errorCode ?? sprintf('IPSCOPE_HTTP_%d', $status),
            $status,
            $previous
        );
    }
}

/**
 * Thrown on HTTP 401 Unauthorized or 403 Forbidden.
 */
final class IpScopeAuthenticationException extends IpScopeApiException
{
    public function __construct(
        string $message,
        int $status,
        string $path,
        ?RateLimitMetadata $rateLimit = null
    ) {
        parent::__construct(
            $message,
            $status,
            $path,
            $status === 401 ? 'IPSCOPE_UNAUTHORIZED' : 'IPSCOPE_FORBIDDEN_SCOPE',
            $rateLimit
        );
    }
}

/**
 * Thrown on HTTP 429 Too Many Requests when retries are exhausted or disabled.
 */
final class IpScopeRateLimitException extends IpScopeApiException
{
    public function __construct(
        string $message,
        string $path,
        public readonly ?float $retryAfterSeconds = null,
        ?RateLimitMetadata $rateLimit = null
    ) {
        parent::__construct($message, 429, $path, 'IPSCOPE_RATE_LIMITED', $rateLimit);
    }
}
