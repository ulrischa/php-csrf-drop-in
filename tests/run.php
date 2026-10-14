<?php

declare(strict_types=1);

require_once __DIR__ . '/../Csrf.php';

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $message);
    }

    echo 'PASS: ' . $message . "\n";
}

function assert_throws(callable $callback, string $exceptionClass, string $message): void
{
    try {
        $callback();
    } catch (Throwable $exception) {
        assert_true($exception instanceof $exceptionClass, $message);
        return;
    }

    throw new RuntimeException('FAIL: ' . $message);
}

Csrf::start();
assert_true(session_status() === PHP_SESSION_ACTIVE, 'Session starts automatically');

$first = Csrf::token('contact');
assert_true((bool) preg_match('/\A[a-f0-9]{64}\z/D', $first), 'Token uses 32 random bytes encoded as hex');
assert_true($first === Csrf::token('contact'), 'Token is stable for the form');
assert_true($first !== Csrf::token('other'), 'Forms have separate tokens');
assert_true(Csrf::validate($first, 'contact'), 'Correct token validates');
assert_true(!Csrf::validate($first, 'other'), 'Token cannot be reused with another form');
assert_true(!Csrf::validate(null, 'contact'), 'Missing token fails closed');
assert_true(!Csrf::validate(['x'], 'contact'), 'Array-shaped token fails closed');
assert_true(!Csrf::validate(str_repeat('z', 64), 'contact'), 'Incorrect token fails closed');
assert_true(!Csrf::validate(str_repeat('x', 200000), 'contact'), 'Oversized token fails closed');
assert_true(!Csrf::validate($first, 'missing'), 'Validation does not mint a token');
assert_true(!isset($_SESSION['_csrf_tokens']['missing']), 'Missing token is not created by validation');

$field = Csrf::field('contact');
assert_true(strpos($field, 'name="_csrf"') !== false, 'Hidden field has expected name');
assert_true(strpos($field, 'value="' . $first . '"') !== false, 'Hidden field contains the token');

$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = ['_csrf' => $first];
assert_true(!Csrf::check('contact'), 'GET is not accepted as a protected POST');
$_SERVER['REQUEST_METHOD'] = 'POST';
assert_true(Csrf::check('contact'), 'Valid POST is accepted');
$_POST = ['_csrf' => ['tampered']];
assert_true(!Csrf::check('contact'), 'POST parameter pollution is rejected');
$_POST = [];
assert_true(!Csrf::check('contact'), 'POST without token is rejected');

Csrf::regenerate('contact');
$rotated = Csrf::token('contact');
assert_true($first !== $rotated, 'Manual regeneration rotates token');
assert_true(!Csrf::validate($first, 'contact'), 'Previous token is invalid immediately');
assert_true(Csrf::validate($rotated, 'contact'), 'Regenerated token validates');

Csrf::setTtl(1);
$_SESSION['_csrf_tokens']['contact']['created_at'] = time() - 1;
assert_true(!Csrf::validate($rotated, 'contact'), 'Expired token is rejected at TTL boundary');
assert_true($_SESSION['_csrf_tokens']['contact']['token'] === $rotated, 'Validation never refreshes expired token');
$renewed = Csrf::token('contact');
assert_true($renewed !== $rotated, 'Rendering refreshes expired token');
assert_true(Csrf::validate($renewed, 'contact'), 'Refreshed token is valid');

$_SESSION['_csrf_tokens']['contact']['created_at'] = time() + 3600;
assert_true(!Csrf::validate($renewed, 'contact'), 'Future-dated session record is rejected');
$renewed = Csrf::token('contact');
$_SESSION['_csrf_tokens']['contact']['created_at'] = 'not-an-int';
assert_true(!Csrf::validate($renewed, 'contact'), 'Malformed timestamp is rejected');
$renewed = Csrf::token('contact');
$_SESSION['_csrf_tokens']['contact']['token'] = 'unexpected value';
assert_true(!Csrf::validate($renewed, 'contact'), 'Corrupted session record fails closed');
assert_true(Csrf::token('contact') !== $renewed, 'Rendering repairs malformed session record');

Csrf::setTtl(null);
$unlimited = Csrf::token('contact');
$_SESSION['_csrf_tokens']['contact']['created_at'] = time() - 86400;
assert_true(Csrf::validate($unlimited, 'contact'), 'Disabled TTL retains token for session lifetime');
Csrf::setTtl(7200);
assert_true(!Csrf::validate($unlimited, 'contact'), 'Configuring TTL applies to existing tokens');

assert_throws(static function (): void { Csrf::setTtl(0); }, InvalidArgumentException::class, 'Zero TTL is rejected');
assert_throws(static function (): void { Csrf::setTtl(-1); }, InvalidArgumentException::class, 'Negative TTL is rejected');
assert_throws(static function (): void { Csrf::token(''); }, InvalidArgumentException::class, 'Empty form ID is rejected');

$_SESSION['_csrf_tokens'] = 'corrupt';
assert_true(!Csrf::validate($first, 'contact'), 'Corrupted session store fails closed');
assert_true(strlen(Csrf::token('contact')) === 64, 'Rendering repairs corrupted session store');

echo "All CSRF tests passed.\n";
