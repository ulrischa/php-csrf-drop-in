<?php

declare(strict_types=1);

require_once __DIR__ . '/../Csrf.php';

// Existing PHP sessions must remain exactly as configured by their application.
session_name('legacyapp');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/legacy',
    'secure' => false,
    'httponly' => false,
    'samesite' => 'Lax',
]);
ini_set('session.use_strict_mode', '0');
session_start();

$sessionId = session_id();
$cookie = session_get_cookie_params();
Csrf::start();
$token = Csrf::token('legacy-form');
if (!Csrf::validate($token, 'legacy-form')
    || session_name() !== 'legacyapp'
    || session_id() !== $sessionId
    || session_get_cookie_params() !== $cookie) {
    throw new RuntimeException('Existing session was modified');
}

try {
    Csrf::assertSecureSession();
    throw new LogicException('Audit failed to report insecure configuration');
} catch (RuntimeException $error) {
    // Expected because the legacy application's cookie configuration is weak.
}

try {
    Csrf::startSecureSession();
    throw new RuntimeException('Active session was not rejected');
} catch (LogicException $error) {
    // Existing sessions are never reconfigured.
}

if (session_name() !== 'legacyapp' || session_id() !== $sessionId) {
    throw new RuntimeException('Active session changed');
}

fwrite(STDOUT, "Existing session compatibility tests passed.\n");
