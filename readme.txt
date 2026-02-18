=== Birdhouse Fancy SMTP Monitor ===
Contributors: birdhouseweb
Tags: smtp, email monitor, wordpress email, api
Requires at least: 5.4
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.0.25
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

= 1.0.25 =
* Re-release from current main commit to align tag, code, and packaged asset
* No functional changes beyond release alignment and version bump

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
