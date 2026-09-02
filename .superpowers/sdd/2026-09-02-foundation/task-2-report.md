# Task 2 Report: Enforce environment configuration

## RED

Command:

```text
PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test tests/Unit/Foundation/EnvironmentValidatorTest.php
```

Output: 2 tests errored because `App\Application\Foundation\EnvironmentValidator` was not found (the expected missing-class failure).

## GREEN

Focused tests and valid command:

```text
PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test tests/Unit/Foundation/EnvironmentValidatorTest.php
```

Output: `{"tool":"phpunit","result":"passed","tests":2,"passed":2,"assertions":2,"duration_ms":1}`

```text
PATH=/opt/homebrew/opt/php/bin:$PATH APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= DB_CONNECTION=mysql DB_DATABASE=sbmtag DB_USERNAME=sbmtag_app php artisan environment:validate
```

Output: `Environment configuration is valid.` (exit 0)

Invalid production command exited 1 and emitted the four required errors in order: DB_CONNECTION, APP_DEBUG, APP_URL, and SESSION_SECURE_COOKIE.

Full suite:

```text
PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test
```

Output: `{"tool":"phpunit","result":"passed","tests":6,"passed":6,"assertions":15,"duration_ms":48}`

## Files

- `app/Application/Foundation/EnvironmentValidator.php`
- `app/Application/Foundation/InvalidEnvironmentConfiguration.php`
- `app/Console/Commands/ValidateEnvironmentCommand.php`
- `config/app.php` (APP_TIMEZONE-backed timezone)
- `tests/Unit/Foundation/EnvironmentValidatorTest.php`

## Self-review

- The validator contract, exact error strings/order, exception `$errors` property, command signature, and success/failure return codes match the brief.
- `git diff --check` passed.
- No release-domain code was touched.

## Concerns

None.
