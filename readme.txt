=== Birdhouse Fancy SMTP Monitor ===
Contributors: birdhouseweb
Tags: smtp, email monitor, wordpress email, api
Requires at least: 5.4
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.0.35
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight child-site companion for Birdhouse Fancy SMTP Dashboard.

== Description ==

Birdhouse Fancy SMTP Monitor is installed on child WordPress sites and responds to secure verification checks from a central Birdhouse Fancy SMTP Dashboard site.

Core behavior:
- Exposes status and token-sync REST endpoints for the manager plugin
- Supports manual verification checks that trigger a real `wp_mail()` send
- Supports lightweight auto checks (no child email send in healthy mode)
- Uses token-based authentication for remote status checks
- Provides a Token Sync Key workflow for secure token retrieval by manager site

== Installation ==

1. Upload the plugin ZIP or folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Open `Settings > SMTP Monitor`.
4. Copy the **Token Sync Key** and use it in the manager dashboard monitor record.

== Changelog ==

= 1.0.35 =
* Remove valid-token manual check throttling that could cause false failed results while keeping invalid-token rate protection.

= 1.0.34 =
* Confirm successful FluentSMTP sends even when the provider key cannot be reliably read, while still failing simulation mode

= 1.0.33 =
* Treat successful FluentSMTP sends as confirmed managed mail transport when a real provider is configured
* Continue failing FluentSMTP simulation mode because it does not confirm external delivery

= 1.0.32 =
* Treat successful WP Mail SMTP API mailers, including Google/Gmail, as confirmed managed mail transport

= 1.0.31 =
* Switched update checks from GitHub API discovery to a public metadata file to avoid API 403/rate-limit failures on child sites

= 1.0.30 =
* Manual verification now reports failure when WordPress accepts mail without confirming SMTP transport
* Added response details for email accepted, SMTP confirmed, delivery method, SMTP host, and recipient

= 1.0.29 =
* Bumped package version so MainWP and GitHub updater can detect the clean rollout build as a newer update

= 1.0.28 =
* Test release to verify GitHub release asset distribution and update detection

= 1.0.27 =
* Added monitor plugin version metadata to status and token API responses
* Avoided rate limiting valid lightweight auto checks while preserving rate limits for manual email sends and invalid token attempts
* Hardened REST/admin handling with safer redirects, sanitized request data, and consistent no-cache API responses

= 1.0.26 =
* Added updater bootstrap safety checks so incomplete release bundles do not break activation
* Added support for token sync via the `X-BFSM-Sync-Key` header with legacy query fallback

= 1.0.24 =
* Added header-based Token Sync Key support (`X-BFSM-Sync-Key`)
* Kept legacy query-key fallback for compatibility
* Reduced exposure by removing sync key from displayed token URL

= 1.0.23 =
* Aligned manual notification behavior with dashboard visibility goals
* Minor consistency and workflow refinements for testing

= 1.0.22 =
* Added Token Sync Key support for secured token retrieval
* Improved token endpoint protections and rate limiting
* Added header-based status auth support (`X-BFSM-Token`) with compatibility fallback
* Improved mail filter safety and cleanup around status checks

= 1.0.21 =
* Initial public monitor build with dashboard integration
* Added child-site status and token REST endpoints
* Added GitHub-based update checker integration
