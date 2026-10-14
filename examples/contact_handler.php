<?php

declare(strict_types=1);

require_once __DIR__ . '/../Csrf.php';

/**
 * Validate the request before performing any state-changing operation.
 *
 * @return array{error: string|null, name: string, success: bool}
 */
function handle_request(): array
{
    $result = ['error' => null, 'name' => '', 'success' => false];

    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return $result;
    }

    $name = $_POST['name'] ?? null;
    $result['name'] = is_string($name) ? $name : '';

    if (!Csrf::check('contact')) {
        http_response_code(403);
        $result['error'] = 'The form has expired or the security token is invalid. Please submit again.';
        return $result;
    }

    if (!is_string($name) || trim($name) === '') {
        $result['error'] = 'Please enter your name.';
        return $result;
    }

    // Perform the application action here, after CSRF and input validation.
    $result['success'] = true;

    return $result;
}
