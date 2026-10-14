<?php

declare(strict_types=1);

require_once __DIR__ . '/../Csrf.php';

function ensure(bool $ok, string $message): void
{
    if (!$ok) {
        throw new RuntimeException($message);
    }
}

function expect_error(callable $action, string $type): void
{
    try {
        $action();
    } catch (Throwable $error) {
        ensure($error instanceof $type, 'Wrong exception: ' . get_class($error));
        return;
    }
    throw new RuntimeException('Expected exception: ' . $type);
}

// Invalid settings must be rejected before starting the session.
foreach ([
    ['unknown' => true],
    ['name' => ''],
    ['name' => '1234'],
    ['name' => 'a bad name'],
    ['same_site' => 'None'],
    ['lifetime' => -1],
    ['lifetime' => '300'],
] as $options) {
    expect_error(static function () use ($options): void {
        Csrf::startSecureSession($options);
    }, InvalidArgumentException::class);
}
ensure(session_status() === PHP_SESSION_NONE, 'Invalid options started a session');

// An audit must neither start nor modify an application's session.
ini_set('session.use_strict_mode', '0');
expect_error(static function (): void {
    Csrf::assertSecureSession();
}, RuntimeException::class);
ensure(session_status() === PHP_SESSION_NONE, 'Audit started a session');
ensure(ini_get('session.use_strict_mode') === '0', 'Audit modified settings');

Csrf::startSecureSession([
    'name' => '__Host-myapp',
    'same_site' => 'Strict',
    'lifetime' => 600,
]);

$cookie = session_get_cookie_params();
ensure(session_status() === PHP_SESSION_ACTIVE, 'Secure session not active');
ensure(session_name() === '__Host-myapp', 'Session name mismatch');
ensure($cookie['secure'] === true, 'Secure flag missing');
ensure($cookie['httponly'] === true, 'HttpOnly flag missing');
ensure($cookie['samesite'] === 'Strict', 'SameSite flag missing');
ensure($cookie['path'] === '/', 'Path mismatch');
ensure($cookie['domain'] === '', 'Domain should be omitted');
ensure($cookie['lifetime'] === 600, 'Lifetime mismatch');
ensure(ini_get('session.use_strict_mode') === '1', 'Strict session ID mode missing');
ensure(ini_get('session.use_cookies') === '1', 'Cookies disabled');
ensure(ini_get('session.use_only_cookies') === '1', 'Only-cookies mode disabled');
ensure(ini_get('session.use_trans_sid') === '0', 'URL session IDs enabled');
ensure(Csrf::validate(Csrf::token('example'), 'example'), 'CSRF token validation failed');
Csrf::assertSecureSession();

expect_error(static function (): void {
    Csrf::startSecureSession();
}, LogicException::class);
ensure(session_name() === '__Host-myapp', 'Active session name changed');

fwrite(STDOUT, "Secure session tests passed.\n");
