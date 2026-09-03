# Task 6: Shared Bootstrap application shell

## RED/GREEN

- RED: `PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test tests/Feature/Foundation/ApplicationShellTest.php` failed as expected because the stock welcome page did not contain `Release Governance`.
- GREEN: the same focused test passed after the controller, route, layout, and components were added (1 test, 5 assertions).

## Verification

- Focused test: passed (1 test, 5 assertions).
- Production build: `source /Users/jaydudhee/.nvm/nvm.sh && nvm use 22.22.3 >/dev/null && npm run build` passed with Vite 8.2.2. It emitted a manifest, versioned CSS/JS, and local Bootstrap Icon `.woff`/`.woff2` files.
- Full suite: `PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test` passed (18 tests, 70 assertions).
- `git diff --check` passed.

## Files

- Added `WelcomeController`, application layout, navbar/sidebar components, Bootstrap Sass entry point, and shell feature test.
- Updated `/` to use the invokable controller; `/health` and `/ready` remain unchanged.
- Updated Vite to load local Bootstrap assets, removed the prior Tailwind/Bunny configuration, and deleted the unused CSS entry point.

## Self-review

- Shell supplies semantic navigation, a skip link targeting the focusable main region, responsive Bootstrap navbar classes, and a fixed-width sidebar suitable for the requested foundation scope.
- Vite asset output is local and therefore compatible with the existing CSP; no SPA framework was added.
- Authentication/dashboard behavior remains only a disabled Phase 2 notice.

## Concerns

- The build succeeds but Bootstrap 5.3 Sass produces upstream Dart Sass deprecation warnings for legacy `@import` and built-ins. The task-required imports remain unchanged.

## Fix round 1

### Changes

- The CSP is now environment-aware. Production and testing retain the unchanged strict policy. Local development adds only the configured Vite origin to `script-src`, `style-src`, and `connect-src`, with its WebSocket equivalent and the inline-style allowance required by Vite HMR.
- `VITE_DEV_SERVER_ORIGIN` is explicitly shared by `.env.example`, the Vite server origin, and Laravel's security configuration; its default is `http://localhost:5173`.
- The header and sidebar are distinct named navigation landmarks: `Application header` labels the top navigation and `Primary navigation` labels the nested sidebar `<nav>`, not its `<aside>` container.

### RED/GREEN and verification

- RED: the new local-CSP and landmark assertions failed against the prior strict-all-environment policy and prior label placement.
- GREEN: `PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test tests/Feature/Foundation/SecurityHeadersTest.php tests/Feature/Foundation/ApplicationShellTest.php` passed (5 tests, 26 assertions).
- Full suite: `PATH=/opt/homebrew/opt/php/bin:$PATH php artisan test` passed (20 tests, 79 assertions).
- Build: Node `v22.22.3`; `npm run build` passed and emitted the local production assets. It retains the pre-existing Bootstrap Sass deprecation warnings.
- `git diff --check` passed.

### Scope and self-review

- No production/testing CSP source, HSTS behavior, `/health`, `/ready`, or authentication/dashboard scope was weakened or changed.
- The deferred Tailwind dependency cleanup was intentionally not touched.
