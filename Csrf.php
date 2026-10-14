<?php

declare(strict_types=1);

/**
 * Session-backed CSRF protection for traditional HTML forms.
 *
 * Tokens remain reusable until they expire or are explicitly regenerated.
 * Hardened session initialization is optional; active sessions are never modified.
 */
final class Csrf
{
    private const SESSION_KEY = '_csrf_tokens';
    private const FIELD_NAME = '_csrf';
    private const TOKEN_BYTES = 32;

    /** @var int|null Token lifetime in seconds; null disables the extra expiry. */
    private static $ttl = 7200;

    /**
     * Configure and start a hardened PHP session explicitly, before any output.
     * Existing active sessions are never reconfigured.
     *
     * Supported options: name, same_site (Lax or Strict), lifetime (seconds).
     * Secure, HttpOnly, root path and host-only cookie scope are mandatory.
     *
     * @param array<string, mixed> $options
     */
    public static function startSecureSession(array $options = []): void
    {
        if (session_status() !== PHP_SESSION_NONE) {
            throw new LogicException('CSRF: Secure session setup requires an inactive session.');
        }

        if (headers_sent()) {
            throw new RuntimeException('CSRF: Secure session setup must happen before output.');
        }

        foreach ($options as $key => $value) {
            if (!in_array($key, ['name', 'same_site', 'lifetime'], true)) {
                throw new InvalidArgumentException('CSRF: Unknown secure session option.');
            }
        }

        $options += [
            'name' => '__Host-csrf',
            'same_site' => 'Lax',
            'lifetime' => 0,
        ];

        $name = $options['name'];
        $sameSite = $options['same_site'];
        $lifetime = $options['lifetime'];

        if (!is_string($name) || !preg_match('/\A(?=.*[A-Za-z])[A-Za-z0-9_-]{1,128}\z/D', $name)) {
            throw new InvalidArgumentException('CSRF: Invalid PHP session name.');
        }

        if (!is_string($sameSite) || !in_array($sameSite, ['Lax', 'Strict'], true)) {
            throw new InvalidArgumentException('CSRF: SameSite must be Lax or Strict.');
        }

        if (!is_int($lifetime) || $lifetime < 0) {
            throw new InvalidArgumentException('CSRF: Cookie lifetime must be a non-negative integer.');
        }

        // Fail instead of silently continuing with weaker PHP session settings.
        foreach ([
            'session.use_strict_mode' => '1',
            'session.use_cookies' => '1',
            'session.use_only_cookies' => '1',
            'session.use_trans_sid' => '0',
        ] as $setting => $value) {
            if (ini_set($setting, $value) === false) {
                throw new RuntimeException('CSRF: Cannot configure ' . $setting . '.');
            }
        }

        if (session_name($name) === false) {
            throw new RuntimeException('CSRF: Cannot set the PHP session name.');
        }

        // Omit Domain to satisfy the browser's __Host- cookie requirements.
        if (!session_set_cookie_params([
            'lifetime' => $lifetime,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => $sameSite,
        ])) {
            throw new RuntimeException('CSRF: Cannot configure session cookie parameters.');
        }

        self::assertSecureSession();
        self::start();
    }

    /**
     * Audit PHP session settings without changing or starting a session.
     * Does not verify TLS termination, session storage, or browser behavior.
     */
    public static function assertSecureSession(): void
    {
        $settings = [
            'session.use_strict_mode' => '1',
            'session.use_cookies' => '1',
            'session.use_only_cookies' => '1',
            'session.use_trans_sid' => '0',
        ];

        foreach ($settings as $name => $expected) {
            if (ini_get($name) !== $expected) {
                throw new RuntimeException('CSRF: Insecure session setting: ' . $name . '.');
            }
        }

        $cookie = session_get_cookie_params();
        if (
            !$cookie['secure']
            || !$cookie['httponly']
            || $cookie['path'] !== '/'
            || $cookie['domain'] !== ''
            || !in_array($cookie['samesite'] ?? '', ['Lax', 'Strict'], true)
        ) {
            throw new RuntimeException('CSRF: Insecure session cookie parameters.');
        }
    }

    /**
     * Start the existing application session if needed.
     *
     * Configure session cookie options before the first session is started.
     */
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        if (headers_sent()) {
            throw new RuntimeException('CSRF: Start the session before sending output.');
        }

        if (!session_start()) {
            throw new RuntimeException('CSRF: Could not start the PHP session.');
        }
    }

    /**
     * Set the token lifetime in seconds, or null to use the session lifetime.
     * Set this early and consistently on every request.
     */
    public static function setTtl(?int $seconds): void
    {
        if ($seconds !== null && $seconds < 1) {
            throw new InvalidArgumentException('CSRF: Token lifetime must be positive or null.');
        }

        self::$ttl = $seconds;
    }

    /**
     * Return a stable token for the form, replacing missing or expired tokens.
     */
    public static function token(string $formId = 'default'): string
    {
        self::assertFormId($formId);
        self::start();

        $record = self::getRecord($formId);

        if (!self::isCurrent($record)) {
            self::regenerate($formId);
            $record = self::getRecord($formId);
        }

        // regenerate() always stores a valid record.
        return $record['token'];
    }

    /**
     * Return a ready-to-use HTML hidden field for the selected form.
     */
    public static function field(string $formId = 'default'): string
    {
        return '<input type="hidden" name="' . self::FIELD_NAME . '" value="'
            . htmlspecialchars(self::token($formId), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
            . '">';
    }

    /**
     * Validate a supplied token without creating or refreshing a token.
     * Accept mixed input so malformed POST fields safely return false.
     *
     * @param mixed $token
     */
    public static function validate($token, string $formId = 'default'): bool
    {
        self::assertFormId($formId);
        self::start();

        if (!is_string($token) || strlen($token) !== self::TOKEN_BYTES * 2) {
            return false;
        }

        $record = self::getRecord($formId);

        if (!self::isCurrent($record)) {
            return false;
        }

        return hash_equals($record['token'], $token);
    }

    /**
     * Validate the hidden field from a POST request.
     * Returns false for any other HTTP method.
     */
    public static function check(string $formId = 'default'): bool
    {
        self::assertFormId($formId);

        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            return false;
        }

        return self::validate($_POST[self::FIELD_NAME] ?? null, $formId);
    }

    /**
     * Stop processing with HTTP 403 when POST token validation fails.
     * Call before any output or state-changing operation.
     */
    public static function enforce(string $formId = 'default'): void
    {
        if (self::check($formId)) {
            return;
        }

        http_response_code(403);
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Forbidden');
    }

    /**
     * Immediately invalidate the existing form token and create a new one.
     * This also invalidates tokens held in other open tabs for that form.
     */
    public static function regenerate(string $formId = 'default'): void
    {
        self::assertFormId($formId);
        self::start();

        if (!isset($_SESSION[self::SESSION_KEY]) || !is_array($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = [];
        }

        $_SESSION[self::SESSION_KEY][$formId] = [
            'token' => bin2hex(random_bytes(self::TOKEN_BYTES)),
            'created_at' => time(),
        ];
    }

    /**
     * Reject empty names instead of silently sharing an unexpected token.
     */
    private static function assertFormId(string $formId): void
    {
        if ($formId === '') {
            throw new InvalidArgumentException('CSRF: Form ID must not be empty.');
        }
    }

    /**
     * Read only records belonging to this session; never initialize on check.
     *
     * @return mixed
     */
    private static function getRecord(string $formId)
    {
        $records = $_SESSION[self::SESSION_KEY] ?? null;

        if (!is_array($records)) {
            return null;
        }

        return $records[$formId] ?? null;
    }

    /**
     * Validate record shape, creation time, and optional absolute expiry.
     *
     * @param mixed $record
     */
    private static function isCurrent($record): bool
    {
        if (!is_array($record)) {
            return false;
        }

        $token = $record['token'] ?? null;
        $createdAt = $record['created_at'] ?? null;
        $now = time();

        if (
            !is_string($token)
            || strlen($token) !== self::TOKEN_BYTES * 2
            || preg_match('/\A[a-f0-9]{64}\z/D', $token) !== 1
            || !is_int($createdAt)
            || $createdAt < 1
            || $createdAt > $now
        ) {
            return false;
        }

        return self::$ttl === null || ($now - $createdAt) < self::$ttl;
    }
}
