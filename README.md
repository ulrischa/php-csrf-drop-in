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

The class reuses PHP sessions without changing their configuration. Hardened session startup is optionally available for new applications; see below.

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
| **Csrf::start()** | Start or reuse the normal PHP session without changing its configuration. |
| **Csrf::startSecureSession($options = [])** | Opt in to hardened session creation before output. |
| **Csrf::assertSecureSession()** | Audit the current PHP configuration without modifying it. |

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

## Secure session configuration (optional)

Existing applications can keep using **Csrf::start()**, **Csrf::field()**, and **Csrf::check()** without any changes. The class reuses an active PHP session and never silently renames it or changes its cookie attributes.

### New applications: hardened setup

On **HTTPS**, call this once at the beginning of **every request**, before any output or calls to session_start() or other CSRF methods:

~~~php
<?php
require_once __DIR__ . '/Csrf.php';

Csrf::startSecureSession([
    'name' => '__Host-myapp',
    'same_site' => 'Lax',
    'lifetime' => 0,
]);
~~~

Defaults: **name = __Host-csrf**, **same_site = Lax**, **lifetime = 0** (browser session). Choose a different __Host- name for each application on the same hostname to avoid collisions. A non-negative lifetime in seconds and **SameSite=Strict** are also supported. Unknown option names, invalid names, and invalid values cause an exception.

The initializer enforces **Secure**, **HttpOnly**, **Path=/**, **no Domain**, and **SameSite=Lax or Strict**. It enables **session.use_strict_mode**, **session.use_cookies**, **session.use_only_cookies**, and disables **session.use_trans_sid**. These security-sensitive settings cannot be weakened through the initializer. The __Host- prefix is enforced by compatible browsers when the matching attributes are present, not by PHP itself.

Secure cookies require HTTPS in production; over ordinary HTTP they will not be sent back by browsers. Behind a TLS-terminating reverse proxy, configure the proxy and application TLS policy separately. The class does not infer security from potentially untrusted forwarded headers.

**Important:** This initializes the normal PHP session, not an additional CSRF-only session. If a PHP session already exists (including session.auto_start), **startSecureSession() throws LogicException** and never modifies it. Set up the session once in your application's bootstrap code.

### Existing applications: optional security audit

To **check** the current configuration without changing it or starting any session, use:

~~~php
require_once __DIR__ . '/Csrf.php';

// After configuring your application's PHP session:
Csrf::assertSecureSession(); // Throws RuntimeException on failure.
~~~

The audit checks the PHP settings above and requires cookie Secure, HttpOnly, SameSite Lax/Strict, root path, and no Domain. This is an **intentionally strict policy**: a legacy app with a legitimately restricted cookie path may fail the audit but may continue using CSRF protection without calling it. A passing audit cannot establish whether HTTPS, browser handling, previously issued cookies, session storage, or custom PHP save handlers are secure. If using a custom session save handler, confirm that strict mode truly rejects unknown session IDs.

**Session IDs remain the application's responsibility:** regenerate them on login and privilege changes with session_regenerate_id(true), and invalidate the session on logout. **Csrf::regenerate()** rotates a form token, **not** the PHP session ID.

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
php tests/secure_session.php
php tests/existing_session.php
bash tests/http_smoke.sh
~~~

The unit tests exercise form isolation, token shape, invalid input, GET/POST checking, rotation, expired/future timestamps, malformed session data, configurable TTL, secure session startup, and legacy session compatibility. The HTTP test requires **curl** and the PHP built-in server; it checks live session cookies, success and 403 responses, repeated submissions, and output escaping.

GitHub Actions tests PHP **7.4, 8.2, 8.4, and 8.5** for push and pull requests.

## License

No license has been selected yet. The repository owner can add one to grant reuse/redistribution rights.
