<?php

declare(strict_types=1);

namespace IpScope\Sdk;

use Closure;
use CurlHandle;
use JsonException;

/**
 * Memory-safe HTTP transport with streaming 2 MiB response ceiling,
 * pre-OOM heap headroom guard (CVE-2026-109618), bounded JSON decoding depth,
 * and automatic exponential backoff with jitter.
 */
final class HttpTransport
{
    public const SDK_VERSION = '0.1.0';
    public const DEFAULT_BASE_URL = 'https://api.ipscope.io';
    public const DEFAULT_TIMEOUT_SECONDS = 5.0;
    public const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MiB hard ceiling
    public const MAX_JSON_DEPTH = 16;

    private string $apiKey;
    private string $baseUrl;
    private float $timeoutSeconds;
    private RetryOptions $retry;
    private string $userAgent;
    private int $minFreeHeadroomBytes;
    private ?Closure $customTransport;
    private ?CurlHandle $curlHandle = null;
    private ?RateLimitMetadata $lastRateLimit = null;

    /**
     * @param null|callable(string, string, array<string, string>, ?string, float): array{status: int, headers?: array<string, string>, body: string} $customTransport
     */
    public function __construct(
        string $apiKey,
        string $baseUrl = self::DEFAULT_BASE_URL,
        float $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        ?RetryOptions $retry = null,
        ?string $userAgent = null,
        int $minFreeHeadroomBytes = IpScopeSecurity::DEFAULT_MIN_FREE_BYTES,
        ?callable $customTransport = null
    ) {
        $this->apiKey = IpScopeValidator::validateApiKey($apiKey);
        $this->baseUrl = rtrim(trim($baseUrl) !== '' ? trim($baseUrl) : self::DEFAULT_BASE_URL, '/');
        $this->timeoutSeconds = $timeoutSeconds > 0.0 ? $timeoutSeconds : self::DEFAULT_TIMEOUT_SECONDS;
        $this->retry = $retry ?? new RetryOptions();
        $this->userAgent = $userAgent !== null && trim($userAgent) !== ''
            ? trim($userAgent)
            : sprintf('ipscope-sdk-php/%s (PHP/%s)', self::SDK_VERSION, PHP_VERSION);
        $this->minFreeHeadroomBytes = $minFreeHeadroomBytes;
        $this->customTransport = $customTransport !== null ? Closure::fromCallable($customTransport) : null;
    }

    public function __destruct()
    {
        $this->close();
    }

    public function close(): void
    {
        $this->curlHandle = null;
        $this->lastRateLimit = null;
    }

    public function getLastRateLimit(): ?RateLimitMetadata
    {
        return $this->lastRateLimit;
    }

    /**
     * Executes an HTTP request and returns decoded JSON associative array + rate-limit metadata.
     *
     * @param array<string, mixed>|null $jsonBody
     * @return array{data: array<string, mixed>, rateLimit: ?RateLimitMetadata}
     */
    public function requestJson(
        string $method,
        string $path,
        ?array $jsonBody = null,
        ?RequestOptions $options = null
    ): array {
        $normalizedPath = str_starts_with($path, '/') ? $path : '/' . $path;
        $url = $this->baseUrl . $normalizedPath;
        $timeout = $options?->timeoutSeconds ?? $this->timeoutSeconds;

        $headers = [
            'Accept' => 'application/json',
            'X-API-Key' => $this->apiKey,
            'User-Agent' => $this->userAgent,
        ];
        if ($options !== null) {
            foreach ($options->headers as $k => $v) {
                $headers[$k] = $v;
            }
        }

        $encodedBody = null;
        if ($jsonBody !== null) {
            $headers['Content-Type'] = 'application/json';
            try {
                $encodedBody = json_encode($jsonBody, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            } catch (JsonException $e) {
                throw new IpScopeValidationException('Failed to serialize request JSON payload: ' . $e->getMessage());
            }
        }

        $maxAttempts = max(1, $this->retry->maxRetries + 1);
        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            $rawResp = $this->executeRaw($method, $normalizedPath, $url, $headers, $encodedBody, $timeout);
            $status = $rawResp['status'];
            $respHeaders = $rawResp['headers'];
            $rawBody = $rawResp['body'];

            $rateLimit = self::extractRateLimitMetadata($respHeaders);
            if ($rateLimit !== null) {
                $this->lastRateLimit = $rateLimit;
            }

            if ($status >= 200 && $status < 300) {
                $decoded = $this->decodeBoundedJson($rawBody, $normalizedPath, $status, $rateLimit);
                return [
                    'data' => $decoded,
                    'rateLimit' => $rateLimit,
                ];
            }

            $retryable = ($status === 429 || $status === 502 || $status === 503 || $status === 504);
            $retryAfterSec = self::parseRetryAfterSeconds($respHeaders['retry-after'] ?? null);

            if ($retryable && $attempt + 1 < $maxAttempts) {
                $delaySec = $this->computeBackoffSeconds($attempt, $retryAfterSec);
                if ($delaySec > 0.0) {
                    usleep((int) round($delaySec * 1_000_000));
                }
                continue;
            }

            $this->throwMappedApiException($status, $normalizedPath, $rawBody, $rateLimit, $retryAfterSec);
        }

        throw new IpScopeApiException('Exhausted retry attempts', 503, $normalizedPath);
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, string>, body: string}
     */
    private function executeRaw(
        string $method,
        string $path,
        string $url,
        array $headers,
        ?string $body,
        float $timeoutSeconds
    ): array {
        // Pre-flight memory headroom check (CVE-2026-109618 mitigation)
        IpScopeSecurity::assertMemoryHeadroom(65536, $this->minFreeHeadroomBytes);

        if ($this->customTransport !== null) {
            $res = ($this->customTransport)($method, $url, $headers, $body, $timeoutSeconds);
            $rawBody = $res['body'] ?? '';
            if (strlen($rawBody) > self::MAX_RESPONSE_BYTES) {
                throw new IpScopeApiException(
                    sprintf('IPScope response exceeded maximum allowed size of %d bytes', self::MAX_RESPONSE_BYTES),
                    502,
                    $path,
                    'IPSCOPE_RESPONSE_TOO_LARGE'
                );
            }
            IpScopeSecurity::assertMemoryHeadroom(strlen($rawBody) * 4, $this->minFreeHeadroomBytes);
            $normHeaders = [];
            foreach (($res['headers'] ?? []) as $k => $v) {
                $normHeaders[strtolower((string) $k)] = (string) $v;
            }
            return [
                'status' => (int) ($res['status'] ?? 500),
                'headers' => $normHeaders,
                'body' => $rawBody,
            ];
        }

        if ($this->curlHandle === null) {
            $ch = curl_init();
            if ($ch === false) {
                throw new IpScopeApiException('Failed to initialize cURL handle', 500, $path, 'IPSCOPE_NETWORK_ERROR');
            }
            $this->curlHandle = $ch;
        } else {
            curl_reset($this->curlHandle);
        }

        $ch = $this->curlHandle;
        $headerLines = [];
        foreach ($headers as $k => $v) {
            $headerLines[] = sprintf('%s: %s', $k, $v);
        }

        $responseHeaders = [];
        $responseChunks = [];
        $receivedBytes = 0;
        $abortedReason = null;
        $minFreeBytes = $this->minFreeHeadroomBytes;

        $timeoutMs = max(1, (int) round($timeoutSeconds * 1000));

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min($timeoutMs, 3000),
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $headerLine) use (&$responseHeaders): int {
                $len = strlen($headerLine);
                $colonPos = strpos($headerLine, ':');
                if ($colonPos !== false) {
                    $name = strtolower(trim(substr($headerLine, 0, $colonPos)));
                    $val = trim(substr($headerLine, $colonPos + 1));
                    if ($name !== '') {
                        $responseHeaders[$name] = $val;
                    }
                }
                return $len;
            },
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (
                &$responseChunks,
                &$receivedBytes,
                &$abortedReason,
                $minFreeBytes
            ): int {
                $chunkLen = strlen($chunk);
                $receivedBytes += $chunkLen;

                if ($receivedBytes > self::MAX_RESPONSE_BYTES) {
                    $abortedReason = 'MAX_RESPONSE_BYTES';
                    return 0; // Abort transfer immediately
                }

                try {
                    IpScopeSecurity::assertMemoryHeadroom($chunkLen * 4, $minFreeBytes);
                } catch (IpScopeMemoryLimitException $e) {
                    $abortedReason = $e;
                    return 0; // Abort transfer before PHP hits fatal memory_limit (CVE-2026-109618)
                }

                $responseChunks[] = $chunk;
                return $chunkLen;
            },
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $ok = curl_exec($ch);
        if ($abortedReason instanceof IpScopeMemoryLimitException) {
            throw $abortedReason;
        }
        if ($abortedReason === 'MAX_RESPONSE_BYTES') {
            throw new IpScopeApiException(
                sprintf('IPScope response exceeded maximum allowed size of %d bytes', self::MAX_RESPONSE_BYTES),
                502,
                $path,
                'IPSCOPE_RESPONSE_TOO_LARGE'
            );
        }

        if ($ok === false) {
            $errno = curl_errno($ch);
            $errMsg = curl_error($ch);
            if ($errno === CURLE_OPERATION_TIMEDOUT) {
                throw new IpScopeTimeoutException($path, $timeoutSeconds);
            }
            throw new IpScopeApiException(
                sprintf('Network error communicating with IPScope API (%s): %s', $path, $errMsg),
                503,
                $path,
                'IPSCOPE_NETWORK_ERROR'
            );
        }

        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $rawBody = implode('', $responseChunks);
        $responseChunks = [];

        return [
            'status' => $status,
            'headers' => $responseHeaders,
            'body' => $rawBody,
        ];
    }

    /**
     * Decodes JSON with bounded recursion depth (`MAX_JSON_DEPTH = 16`) and pre-OOM headroom verification.
     *
     * @return array<string, mixed>
     */
    private function decodeBoundedJson(
        string $rawBody,
        string $path,
        int $status,
        ?RateLimitMetadata $rateLimit
    ): array {
        // JSON AST in Zend Engine takes ~4x the raw byte size
        IpScopeSecurity::assertMemoryHeadroom(strlen($rawBody) * 4, $this->minFreeHeadroomBytes);

        try {
            $decoded = json_decode($rawBody, true, self::MAX_JSON_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new IpScopeApiException(
                'Invalid or excessively nested JSON received from IPScope API: ' . $e->getMessage(),
                $status,
                $path,
                'IPSCOPE_INVALID_JSON',
                $rateLimit,
                $e
            );
        }

        if (!is_array($decoded)) {
            throw new IpScopeApiException(
                'Expected JSON object response from IPScope API.',
                $status,
                $path,
                'IPSCOPE_INVALID_JSON',
                $rateLimit
            );
        }

        return $decoded;
    }

    /**
     * @param array<string, string> $headers
     */
    public static function extractRateLimitMetadata(array $headers): ?RateLimitMetadata
    {
        $limit = self::parseHeaderInt($headers['x-ratelimit-limit'] ?? null);
        $remaining = self::parseHeaderInt($headers['x-ratelimit-remaining'] ?? null);
        $reset = self::parseHeaderInt($headers['x-ratelimit-reset'] ?? null);
        $credits = self::parseHeaderInt($headers['x-ratelimit-credits-remaining'] ?? null);
        $tier = isset($headers['x-ratelimit-tier']) && trim($headers['x-ratelimit-tier']) !== ''
            ? trim($headers['x-ratelimit-tier'])
            : null;

        if ($limit === null && $remaining === null && $reset === null && $credits === null && $tier === null) {
            return null;
        }

        return new RateLimitMetadata(
            limit: $limit,
            remaining: $remaining,
            resetEpochSeconds: $reset,
            creditsRemaining: $credits,
            planTier: $tier,
        );
    }

    private static function parseHeaderInt(?string $raw): ?int
    {
        if ($raw === null) {
            return null;
        }
        $trimmed = trim($raw);
        if ($trimmed === '' || !is_numeric($trimmed)) {
            return null;
        }
        return (int) $trimmed;
    }

    private static function parseRetryAfterSeconds(?string $raw): ?float
    {
        if ($raw === null) {
            return null;
        }
        $trimmed = trim($raw);
        if ($trimmed === '' || !is_numeric($trimmed)) {
            return null;
        }
        $sec = (float) $trimmed;
        return $sec >= 0.0 ? $sec : null;
    }

    private function computeBackoffSeconds(int $attempt, ?float $retryAfterSeconds): float
    {
        if ($retryAfterSeconds !== null && $retryAfterSeconds > 0.0) {
            return min($retryAfterSeconds, $this->retry->maxDelaySeconds);
        }
        $exp = $this->retry->initialDelaySeconds * (2 ** $attempt);
        $capped = min($exp, $this->retry->maxDelaySeconds);
        $jitter = 0.75 + (mt_rand(0, 250) / 1000.0);
        return $capped * $jitter;
    }

    private function throwMappedApiException(
        int $status,
        string $path,
        string $rawBody,
        ?RateLimitMetadata $rateLimit,
        ?float $retryAfterSeconds
    ): never {
        $message = sprintf('IPScope API request to "%s" failed with HTTP %d', $path, $status);
        $errorCode = sprintf('IPSCOPE_HTTP_%d', $status);

        if ($rawBody !== '' && strlen($rawBody) <= 65536) {
            try {
                $parsed = json_decode($rawBody, true, 8, JSON_THROW_ON_ERROR);
                if (is_array($parsed)) {
                    if (isset($parsed['message']) && is_string($parsed['message']) && trim($parsed['message']) !== '') {
                        $message = $parsed['message'];
                    } elseif (isset($parsed['error']) && is_string($parsed['error']) && trim($parsed['error']) !== '') {
                        $message = $parsed['error'];
                    }
                    if (isset($parsed['code']) && is_string($parsed['code'])) {
                        $errorCode = $parsed['code'];
                    }
                }
            } catch (JsonException) {
                // Keep default HTTP status message
            }
        }

        if ($status === 401 || $status === 403) {
            throw new IpScopeAuthenticationException($message, $status, $path, $rateLimit);
        }
        if ($status === 429) {
            throw new IpScopeRateLimitException($message, $path, $retryAfterSeconds, $rateLimit);
        }

        throw new IpScopeApiException($message, $status, $path, $errorCode, $rateLimit);
    }
}
