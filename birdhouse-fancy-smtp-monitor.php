<?php
/**
 * Plugin Name: Birdhouse Fancy SMTP Monitor
 * Description: Responds to remote SMTP status checks from a central manager site.
 * Version: 1.0.7
 * Author: Birdhouse Web Design
 * License: GPL2
 */

if (!defined('ABSPATH')) exit;

// === GitHub Update Checker (Wrapped for Safety) ===
$update_checker_file = plugin_dir_path(__FILE__) . 'plugin-update-checker/plugin-update-checker.php';

if (file_exists($update_checker_file)) {
    require_once $update_checker_file;

    if (class_exists('\YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
        $updateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            'https://github.com/BirdhouseMN/birdhouse-fancy-smtp-monitor',
            __FILE__,
            'birdhouse-fancy-smtp-monitor'
        );
        $updateChecker->getVcsApi()->enableReleaseAssets();
    } else {
        error_log('[BFSM] plugin-update-checker.php included, but PucFactory v5 is not available.');
    }
}
 else {
    error_log('[BFSM] plugin-update-checker.php not found. Skipping GitHub updater.');
}

// === Generate Token on Activation ===
register_activation_hook(__FILE__, function () {
    if (!get_option('bfsmtp_site_token')) {
        $token = wp_generate_password(32, false);
        update_option('bfsmtp_site_token', $token);
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
        wp_redirect(admin_url('options-general.php?page=bfsmtp-monitor-settings&bfsm_regenerated=1'));
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

// === /status Endpoint Callback (tests SMTP, real email for manual only) ===
function bfsmtp_status_check($request) {
    $supplied_token = sanitize_text_field($request->get_param('token'));
    $notify_param   = sanitize_email($request->get_param('notify'));
    $mode           = sanitize_text_field($request->get_param('mode')); // manual or auto
    $stored_token   = get_option('bfsmtp_site_token');

    // === Rate Limiting by IP ===
    $ip_key = 'bfsm_rate_' . md5($_SERVER['REMOTE_ADDR']);
    $recent = get_transient($ip_key);
    if ($recent) {
        return new WP_REST_Response([
            'status'  => 'fail',
            'message' => 'Too many requests. Please wait before trying again.'
        ], 429);
    }
    set_transient($ip_key, true, 30); // 30 second cooldown

    if (!$supplied_token || $supplied_token !== $stored_token) {
        return new WP_REST_Response([
            'status'  => 'fail',
            'message' => 'Invalid token'
        ], 403);
    }

    $subject = '[SMTP Monitor] Test Email';
    $message = "âœ… This is a manual SMTP test triggered from the Birdhouse Manager.\n\nThat means your site successfully responded to a direct ping and sent this email using its current SMTP setup.\n\nIf you're reading this, everything is working as expected! ðŸŽ‰\n\nNo action is needed unless this email lands in spam or has unexpected formatting.";
    $headers = ['Content-Type: text/plain; charset=UTF-8'];

    $to = ($mode === 'auto') 
        ? 'noreply@birdhousemanager.com' 
        : (is_email($notify_param) ? $notify_param : get_option('admin_email'));

    // Force the sender address
    add_filter('wp_mail_from', function () {
        return 'security@birdhousemanager.com';
    });
    add_filter('wp_mail_from_name', function () {
        return 'Birdhouse SMTP Monitor';
    });

    if (defined('BFSM_DEBUG') && BFSM_DEBUG) {
        error_log('[BFSM] Mode: ' . $mode);
        error_log('[BFSM] Attempting to send to: ' . $to);
    }

    ob_start();
    $sent = wp_mail($to, $subject, $message, $headers);
    $debug_output = ob_get_clean();

    if (defined('BFSM_DEBUG') && BFSM_DEBUG) {
        error_log('[BFSM] wp_mail() result: ' . var_export($sent, true));
    }

    $status = $sent ? 'ok' : 'fail';
    $http   = $sent ? 200 : 500;

    return new WP_REST_Response([
        'status'      => $status,
        'email_sent'  => $sent,
        'debug_check' => $debug_output ?: ($sent ? 'Success' : 'wp_mail() returned false'),
        'timestamp'   => current_time('mysql'),
        'email'       => $to,
    ], $http);
}



// === /token Endpoint Callback ===
function bfsmtp_return_token($request) {
    $token = get_option('bfsmtp_site_token');

    if (!$token) {
        return new WP_REST_Response([
            'message' => 'Token not found'
        ], 404);
    }

    return new WP_REST_Response([
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
        if (!empty($_GET['bfsm_regenerated']) && $_GET['bfsm_regenerated'] === '1') {
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

    $token     = get_option('bfsmtp_site_token');
    $site_url  = home_url();
    $ping_url  = esc_url_raw(trailingslashit($site_url) . 'wp-json/smtp-monitor/v1/status?token=' . $token);
    $token_url = esc_url_raw(trailingslashit($site_url) . 'wp-json/smtp-monitor/v1/token');
    ?>
    <div class="wrap">
        <h1>SMTP Monitor Settings</h1>
        <table class="form-table">
            <tr>
                <th scope="row">Monitor Token</th>
                <td><code><?php echo esc_html($token); ?></code></td>
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
