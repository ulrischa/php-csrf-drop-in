# PHP CSRF Drop-in

A small, dependency-free, session-backed CSRF protection class for HTML forms. Include **Csrf.php**: no framework, Composer package, database, or JavaScript is required.

- PHP **7.4 and 8.x**.
- Random tokens per form using **random_bytes(32)**; compare in constant time with **hash_equals()**.
- Optional absolute expiry: **7,200 seconds (2 hours)** by default.
- Tokens work with multiple browser tabs and repeated submissions.
- Missing, malformed, incorrect, and expired tokens fail closed, without refreshing tokens during verification.
- Generate hidden HTML inputs automatically or validate a token from a trusted request header.
- Choose Boolean validation or **HTTP 403 Forbidden** enforcement.

Implements the [OWASP synchronizer token pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for stateful applications.

## Quick start

Include the file before emitting HTML:

~~~php
<?php
require_once __DIR__ . '/Csrf.php';
?>
<form method="post">
    <?= Csrf::field('contact') ?>
    <input name="message" required>
    <button type="submit">Send</button>
</form>
~~~

Check the POST **before processing or changing anything**:

~~~php
<?php
require_once __DIR__ . '/Csrf.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    Csrf::enforce('contact');

    // Validate inputs and authorization; then perform the action.
}
~~~

**Csrf::field('contact')** renders a hidden input named **_csrf**. **Csrf::enforce('contact')** stops invalid requests with HTTP 403. Both calls must use the same server-defined form ID (the default is **default**).

The class automatically starts a PHP session if necessary, but a session must be started before HTML output. Configure secure session cookies centrally (see below).

## Inline error handling

Use **Csrf::check()** rather than **enforce()** to display an error and preserve submitted input:

~~~php
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!Csrf::check('contact')) {
        http_response_code(403);
        $error = 'Security token invalid or expired. Please submit again.';
    } else {
        // Validate input, authorize, and process.
    }
}
~~~

On re-rendering, **Csrf::field()** creates a new token if the old one expired. Escape user input before output using **htmlspecialchars()**.

A runnable two-file example separates [form presentation](examples/contact.php) and [request handling](examples/contact_handler.php). It preserves input and shows errors inline.

## Multiple forms

~~~php
<?= Csrf::field('profile-update') ?>
<?= Csrf::field('delete-account') ?>
~~~

A token for one form cannot be used for another. Check the correct form ID in the matching handler, and never choose it from untrusted request data.

Tokens are reusable until expiry or regeneration. Multiple tabs and repeated form submissions work; the class is **not a one-time transaction or replay-prevention system**. Implement separate idempotency or user confirmations for sensitive operations.

## Timestamp and token expiry

Each token is saved with a **server-side creation timestamp** in the PHP session (the timestamp is not placed in HTML). The default TTL is **2 hours from token creation**, not from the last visit. You can configure it:

~~~php
Csrf::setTtl(1800); // 30 minutes
Csrf::setTtl(null); // No additional expiry beyond the PHP session
~~~

Call **setTtl() consistently on every request, before other CSRF calls**. Only positive integers or null are permitted. Changes affect existing tokens. An expired PHP session always invalidates its tokens, regardless of this setting.

**Csrf::check() / Csrf::validate() / Csrf::enforce()** never renew expired tokens. **Csrf::field() / Csrf::token()** generate new tokens when rendering or requesting a token. Long-open forms can expire and must be resubmitted or reloaded; for such forms, use a longer TTL or disable the extra expiry. TTL adds limited security beyond session protection.

Manually invalidate a form token with:

~~~php
Csrf::regenerate('contact');
~~~

That also invalidates copies of the older token in other browser tabs.

## API

| Method | Function |
| --- | --- |
| **Csrf::field($formId = 'default')** | Return a hidden field; create/renew token. |
| **Csrf::token($formId = 'default')** | Return a token for a form or same-origin JavaScript. |
| **Csrf::check($formId = 'default')** | Validate the **POST** hidden field (false for other methods). |
| **Csrf::validate($token, $formId = 'default')** | Validate a supplied token without renewal. |
| **Csrf::enforce($formId = 'default')** | Reject invalid POST with HTTP 403 and exit. |
| **Csrf::regenerate($formId = 'default')** | Rotate the form token. |
| **Csrf::setTtl($seconds)** | Set lifetime (seconds) or null; default 7,200 seconds. |
| **Csrf::start()** | Start the PHP session if not already active. |

### Fetch / AJAX

You can send the token in a custom header to a trusted same-origin endpoint:

~~~php
<meta name="csrf-token" content="<?= htmlspecialchars(Csrf::token('settings'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
~~~

~~~javascript
const token = document.querySelector('meta[name="csrf-token"]').content;
fetch('/settings', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': token }
});
~~~

~~~php
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    || !Csrf::validate($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null, 'settings')) {
    http_response_code(403);
    exit('Forbidden');
}
// Validate input and authorization before updating anything.
~~~

**check()** and **enforce()** intentionally only allow POST. For PUT/PATCH/DELETE, check the expected method yourself and pass a token from a trusted header or parsed body to **validate()**. Do not place tokens in URLs or query strings.

## Secure session configuration

The class **does not silently alter application session settings**. On HTTPS, configure before starting a session or invoking CSRF methods:

~~~php
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);

session_start();
~~~

Always use HTTPS in production. Consider **SameSite=Strict** for sensitive applications. Avoid broad cookie domains that include less trusted subdomains. Regenerate the PHP session ID at login or privilege changes, invalidate it on logout, and rotate CSRF tokens at authentication boundaries when appropriate.

### Security limitations

- All state-changing endpoints require CSRF protection; never mutate state with GET/HEAD/OPTIONS. SameSite cookies alone are not enough.
- CSRF defense does not replace login, authorization, input validation, XSS prevention, escaping, rate limits, or sensitive-action confirmation. XSS can bypass CSRF tokens.
- Tokens reside in **$_SESSION['_csrf_tokens']**. Do not expose tokens in analytics, logs, cross-origin requests, or URLs.
- Do **not publicly cache** HTML responses containing per-session tokens. Configure **Cache-Control: private, no-store** and ensure caches honor it.
- Never submit tokens to untrusted origins in forms or fetch calls.
- This is for **stateful PHP sessions**, not stateless double-submit cookies.
- The form and handler must share the intended session cookie. Do not close the session before writing a new token.
- Consider Origin/Referer or Fetch Metadata validation as further defense in depth for sensitive apps.
- The global class name **Csrf** is deliberate for simple drop-in usage; namespace or rename if your app already declares that class.

## Tests

No Composer or test framework needed:

~~~bash
php -l Csrf.php
php tests/run.php
bash tests/http_smoke.sh
~~~

The unit tests exercise form isolation, token shape, invalid input, GET/POST checking, rotation, expired/future timestamps, malformed session data, and configurable TTL. The HTTP test requires **curl** and the PHP built-in server; it checks live session cookies, success and 403 responses, repeated submissions, and output escaping.

GitHub Actions tests PHP **7.4, 8.2, 8.4, and 8.5** for push and pull requests.

## License

No license has been selected yet. The repository owner can add one to grant reuse/redistribution rights.
