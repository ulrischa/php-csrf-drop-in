<?php

declare(strict_types=1);

require_once __DIR__ . '/contact_handler.php';

$result = handle_request();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF-protected form</title>
</head>
<body>
    <?php if ($result['error'] !== null): ?>
        <p role="alert"><?= htmlspecialchars($result['error'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></p>
    <?php elseif ($result['success']): ?>
        <p>Form submitted successfully.</p>
    <?php endif; ?>

    <form method="post">
        <?= Csrf::field('contact') ?>
        <label for="name">Name</label>
        <input id="name" name="name" required value="<?= htmlspecialchars($result['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
        <button type="submit">Submit</button>
    </form>
</body>
</html>
