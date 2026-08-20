<?php
/**
 * Plugin Name: Birdhouse Fancy SMTP Monitor
 * Description: Responds to remote SMTP status checks from a central manager site.
 * Version: 1.0.29
 * Author: Birdhouse Web Design
 * License: GPL2
 */

if (!defined('ABSPATH')) exit;

if (!defined('BFSMTP_MONITOR_VERSION')) {
    define('BFSMTP_MONITOR_VERSION', '1.0.29');
}

function bfsmtp_monitor_response_meta() {
    return [
        'child_version'   => BFSMTP_MONITOR_VERSION,
        'plugin_version'  => BFSMTP_MONITOR_VERSION,
        'monitor_version' => BFSMTP_MONITOR_VERSION,
        'plugin_slug'     => 'birdhouse-fancy-smtp-monitor',
    ];
}

function bfsmtp_monitor_rest_response($data, $status = 200) {
    $response = new WP_REST_Response(array_merge($data, bfsmtp_monitor_response_meta()), $status);
    $response->header('Cache-Control', 'no-cache, must-revalidate, max-age=0');
    $response->header('Expires', 'Wed, 11 Jan 1984 05:00:00 GMT');
    $response->header('X-Robots-Tag', 'noindex, nofollow, noarchive');
    return $response;
}

// === GitHub Update Checker (Wrapped for Safety) ===
$bfsm_puc_candidates = [
    [
        'bootstrap' => plugin_dir_path(__FILE__) . 'plugin-update-checker/plugin-update-checker.php',
        'required'  => [],
    ],
    [
        'bootstrap' => plugin_dir_path(__FILE__) . 'plugin-update-checker-5.6/plugin-update-checker.php',
        'required'  => [
            plugin_dir_path(__FILE__) . 'plugin-update-checker-5.6/Puc/v5p6/Autoloader.php',
            plugin_dir_path(__FILE__) . 'plugin-update-checker-5.6/Puc/v5p6/PucFactory.php',
            plugin_dir_path(__FILE__) . 'plugin-update-checker-5.6/Puc/v5/PucFactory.php',
        ],
    ],
];

$bfsm_puc_bootstrap = null;
foreach ($bfsm_puc_candidates as $candidate) {
    if (!file_exists($candidate['bootstrap'])) {
        continue;
    }

    $missing_dependency = false;
    foreach ($candidate['required'] as $required_path) {
        if (!file_exists($required_path)) {
            $missing_dependency = true;
            break;
        }
    }

    if ($missing_dependency) {
        if (defined('BFSM_DEBUG') && BFSM_DEBUG) {
            error_log('[BFSM] Skipping incomplete plugin-update-checker bundle: ' . $candidate['bootstrap']);
        }
        continue;
    }

    $bfsm_puc_bootstrap = $candidate['bootstrap'];
    break;
}

if ($bfsm_puc_bootstrap) {
    require_once $bfsm_puc_bootstrap;

    if (class_exists('\YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
        $updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            'https://github.com/BirdhouseMN/birdhouse-fancy-smtp-monitor',
            __FILE__,
            'birdhouse-fancy-smtp-monitor'
        );

        // Use the main branch and release assets if available.
        if (method_exists($updateChecker, 'setBranch')) {
            $updateChecker->setBranch('main');
        }

        if (method_exists($updateChecker, 'getVcsApi')) {
            $api = $updateChecker->getVcsApi();
            if ($api && method_exists($api, 'enableReleaseAssets')) {
                $api->enableReleaseAssets();
            }
        }
    } elseif (defined('BFSM_DEBUG') && BFSM_DEBUG) {
        error_log('[BFSM] PUC library loaded, but PucFactory v5 is not available.');
    }
} elseif (defined('BFSM_DEBUG') && BFSM_DEBUG) {
    error_log('[BFSM] plugin-update-checker bootstrap not found. Skipping GitHub updater.');
}

// === Generate Token on Activation ===
register_activation_hook(__FILE__, function () {
    if (!get_option('bfsmtp_site_token')) {
        $token = wp_generate_password(32, false);
        update_option('bfsmtp_site_token', $token);
    }
    if (!get_option('bfsmtp_token_sync_secret')) {
        $secret = wp_generate_password(40, false);
        update_option('bfsmtp_token_sync_secret', $secret);
    }
});

// === Handle Token Regeneration Before Output ===
add_action('admin_init', function () {
    if (
        isset($_POST['bfsm_regenerate_token']) &&
        check_admin_referer('bfsm_regenerate_token_action') &&
        current_user_can('manage_options')
    ) {
        $new_token = wp_generate_password(32, false);
        update_option('bfsmtp_site_token', $new_token);
        wp_safe_redirect(admin_url('options-general.php?page=bfsmtp-monitor-settings&bfsm_regenerated=1'));
        exit;
    }
});

// === Register REST Endpoints ===
add_action('rest_api_init', function () {
    register_rest_route('smtp-monitor/v1', '/status', [
        'methods'             => 'GET',
        'callback'            => 'bfsmtp_status_check',
        'permission_callback' => '__return_true',
    ]);

    register_rest_route('smtp-monitor/v1', '/token', [
        'methods'             => 'GET',
        'callback'            => 'bfsmtp_return_token',
        'permission_callback' => '__return_true',
    ]);
});

// === /status Endpoint Callback (tests SMTP; email only for manual mode) ===
function bfsmtp_status_check($request) {
    $header_token   = sanitize_text_field($request->get_header('x-bfsm-token'));
    $query_token    = sanitize_text_field($request->get_param('token'));
    $supplied_token = $header_token ?: $query_token;
    $notify_param   = sanitize_email($request->get_param('notify'));
    $mode_param     = strtolower(sanitize_text_field($request->get_param('mode'))); // manual or auto
    $mode           = in_array($mode_param, ['manual','auto'], true) ? $mode_param : 'manual';
    $stored_token   = get_option('bfsmtp_site_token');

    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';

    if (!$supplied_token || !$stored_token || !hash_equals($stored_token, $supplied_token)) {
        $ip_key = 'bfsm_invalid_rate_' . md5($ip);
        if (get_transient($ip_key)) {
            return bfsmtp_monitor_rest_response([
                'status'  => 'fail',
                'message' => 'Too many requests. Please wait before trying again.'
            ], 429);
        }
        set_transient($ip_key, true, 30);

        return bfsmtp_monitor_rest_response([
            'status'  => 'fail',
            'message' => 'Invalid token'
        ], 403);
    }

    // Rate-limit manual checks because they send real email. Lightweight auto checks stay cheap.
    $ip_key = 'bfsm_rate_' . md5($ip);
    if ($mode === 'manual' && get_transient($ip_key)) {
        return bfsmtp_monitor_rest_response([
            'status'  => 'fail',
            'message' => 'Too many requests. Please wait before trying again.'
        ], 429);
    }
    if ($mode === 'manual') {
        set_transient($ip_key, true, 30);
    }

    // Use a safe From name only. Do not override From address to avoid DMARC conflicts.
    $from_name_filter = function () {
        return 'Birdhouse SMTP Monitor';
    };
    add_filter('wp_mail_from_name', $from_name_filter);

    // Add a Reply-To to your security inbox
    $headers = [
        'Content-Type: text/plain; charset=UTF-8',
        'Reply-To: security@birdhousemanager.com',
    ];

    // Neutral copy works for both manual-button tests and incident verifications
    $subject = '[BFSM] SMTP Verification';
    $message = "This message confirms the site responded to an SMTP verification request from the Birdhouse Manager.\n\n"
             . "The site successfully sent this email using its current SMTP setup.\n\n"
             . "No action is needed unless this message lands in spam or has unexpected formatting.";

    $manual = ($mode === 'manual');

    // Recipient rules:
    // - MANUAL: send to ?notify=; fallback to site admin email if missing.
    // - AUTO: do not send a real email. Only report status.
    $to = $manual
        ? (is_email($notify_param) ? $notify_param : get_option('admin_email'))
        : '';

    if (defined('BFSM_DEBUG') && BFSM_DEBUG) {
        error_log('[BFSM] Mode: ' . $mode);
        error_log('[BFSM] IP: ' . $ip);
        error_log('[BFSM] Attempting to send to: ' . ($to ?: '(auto mode, no email)'));
    }

    if ($manual) {
        ob_start();
        $sent = wp_mail($to, $subject, $message, $headers);
        $debug_output = ob_get_clean();
        remove_filter('wp_mail_from_name', $from_name_filter);
        $status = $sent ? 'ok' : 'fail';
        $http   = $sent ? 200 : 500;

        return bfsmtp_monitor_rest_response([
            'status'      => $status,
            'email_sent'  => (bool) $sent,
            'debug_check' => $debug_output ?: ($sent ? 'Success' : 'wp_mail() returned false'),
            'timestamp'   => current_time('mysql'),
            'email'       => $to,
        ], $http);
    }

    // AUTO: no email is sent. Return an OK if we reached here with a valid token.
    remove_filter('wp_mail_from_name', $from_name_filter);
    return bfsmtp_monitor_rest_response([
        'status'      => 'ok',
        'email_sent'  => false,
        'debug_check' => 'Auto mode check: no email sent',
        'timestamp'   => current_time('mysql'),
        'email'       => null,
    ], 200);
}

// === /token Endpoint Callback ===
function bfsmtp_return_token($request) {
    // Anonymous force-rotation is never allowed.
    $force = sanitize_text_field($request->get_param('force'));
    if ($force === '1') {
        if (!current_user_can('manage_options')) {
            return bfsmtp_monitor_rest_response([
                'status'  => 'fail',
                'message' => 'Unauthorized token rotation request.',
            ], 403);
        }

        $new_token = wp_generate_password(32, false);
        update_option('bfsmtp_site_token', $new_token);

        return bfsmtp_monitor_rest_response([
            'message'   => 'Token regenerated.',
            'token'     => $new_token,
            'timestamp' => current_time('mysql'),
            'site_url'  => home_url(),
        ], 200);
    }

    // Light rate limit to reduce token scraping.
    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
    $ip_key = 'bfsm_token_rate_' . md5($ip);
    if (get_transient($ip_key)) {
        return bfsmtp_monitor_rest_response([
            'status'  => 'fail',
            'message' => 'Too many requests. Please wait before trying again.'
        ], 429);
    }
    set_transient($ip_key, true, 30);

    $stored_secret = get_option('bfsmtp_token_sync_secret');
    if (!$stored_secret) {
        $stored_secret = wp_generate_password(40, false);
        update_option('bfsmtp_token_sync_secret', $stored_secret);
    }
    $header_secret   = sanitize_text_field($request->get_header('x-bfsm-sync-key'));
    $query_secret    = sanitize_text_field($request->get_param('sync_key'));
    $supplied_secret = $header_secret ?: $query_secret;

    if (!current_user_can('manage_options')) {
        if (!$supplied_secret || !hash_equals($stored_secret, $supplied_secret)) {
            return bfsmtp_monitor_rest_response([
                'status'  => 'fail',
                'message' => 'Unauthorized token request.',
            ], 403);
        }
    }

    $token = get_option('bfsmtp_site_token');

    if (!$token) {
        // Regenerate if missing
        $token = wp_generate_password(32, false);
        update_option('bfsmtp_site_token', $token);
    }

    return bfsmtp_monitor_rest_response([
        'token'     => $token,
        'timestamp' => current_time('mysql'),
        'site_url'  => home_url(),
    ], 200);
}

// === Admin Notice for Token Regeneration Confirmation ===
add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) return;

    if (!function_exists('get_current_screen')) {
        require_once ABSPATH . 'wp-admin/includes/screen.php';
    }

    $screen = get_current_screen();
    if ($screen && $screen->id === 'settings_page_bfsmtp-monitor-settings') {
        $regenerated = isset($_GET['bfsm_regenerated']) ? sanitize_text_field(wp_unslash($_GET['bfsm_regenerated'])) : '';
        if ($regenerated === '1') {
            echo '<div class="notice notice-success is-dismissible"><p>Token successfully regenerated.</p></div>';
        }
    }
});

// === Add Settings Page ===
add_action('admin_menu', function () {
    add_options_page(
        'SMTP Monitor Settings',
        'SMTP Monitor',
        'manage_options',
        'bfsmtp-monitor-settings',
        'bfsmtp_render_settings_page'
    );
});

// === Render Settings Page ===
function bfsmtp_render_settings_page() {
    if (!current_user_can('manage_options')) return;

    $token      = get_option('bfsmtp_site_token');
    $sync_key   = get_option('bfsmtp_token_sync_secret');
    $site_url   = home_url();
    $ping_url   = esc_url_raw(trailingslashit($site_url) . 'wp-json/smtp-monitor/v1/status');
    $token_url  = esc_url_raw(trailingslashit($site_url) . 'wp-json/smtp-monitor/v1/token');
    ?>
    <div class="wrap">
        <h1>SMTP Monitor Settings</h1>
        <table class="form-table">
            <tr>
                <th scope="row">Monitor Token</th>
                <td><code><?php echo esc_html($token); ?></code></td>
            </tr>
            <tr>
                <th scope="row">Token Sync Key</th>
                <td><code><?php echo esc_html($sync_key); ?></code></td>
            </tr>
            <tr>
                <th scope="row">Ping URL</th>
                <td><code><?php echo esc_html($ping_url); ?></code></td>
            </tr>
            <tr>
                <th scope="row">Token Sync URL</th>
                <td><code><?php echo esc_html($token_url); ?></code></td>
            </tr>
        </table>
        <form method="post" style="margin-top: 20px;">
            <?php wp_nonce_field('bfsm_regenerate_token_action'); ?>
            <input type="submit" name="bfsm_regenerate_token" class="button button-secondary" value="Regenerate Token" onclick="return confirm('Are you sure you want to regenerate this site\'s token? This will break any existing pings until updated on the manager site.');" />
        </form>
    </div>
    <?php
}
