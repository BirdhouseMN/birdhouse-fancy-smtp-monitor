<?php
/**
 * Plugin Name: Birdhouse Fancy SMTP Monitor
 * Description: Responds to remote SMTP status checks from a central manager site.
 * Version: 1.0.39
 * Author: Birdhouse Web Design
 * License: GPL2
 */

if (!defined('ABSPATH')) exit;

if (!defined('BFSMTP_MONITOR_VERSION')) {
    define('BFSMTP_MONITOR_VERSION', '1.0.39');
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
            'https://raw.githubusercontent.com/BirdhouseMN/birdhouse-fancy-smtp-monitor/main/update.json',
            __FILE__,
            'birdhouse-fancy-smtp-monitor'
        );
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

// === /status Endpoint Callback (tests email delivery for manual and auto modes) ===
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

    // Use a safe From name only. Do not override From address to avoid DMARC conflicts.
    $from_name_filter = function () {
        return 'Birdhouse SMTP Monitor';
    };
    add_filter('wp_mail_from_name', $from_name_filter);

    $headers = [
        'Content-Type: text/plain; charset=UTF-8',
    ];

    $subject = ($mode === 'auto') ? '[BFSM Probe] Automatic Email Verification' : '[BFSM Manual] Email Verification';
    $message = ($mode === 'auto')
        ? "This is an automatic proof email from the Birdhouse SMTP Monitor.\n\n"
            . "The child site successfully sent this email using its current WordPress mail setup.\n\n"
            . "No action is needed unless the manager dashboard reports a failure."
        : "This message confirms a manual email delivery test from the Birdhouse Manager.\n\n"
            . "The child site successfully sent this email using its current WordPress mail setup.\n\n"
            . "No action is needed unless this message lands in spam or has unexpected formatting.";

    // Both manual and auto checks must attempt a real send so "OK" means email delivery worked.
    $to = is_email($notify_param) ? $notify_param : get_option('admin_email');

    if (!is_email($to)) {
        remove_filter('wp_mail_from_name', $from_name_filter);
        return bfsmtp_monitor_rest_response([
            'status'      => 'fail',
            'email_sent'  => false,
            'debug_check' => 'No valid recipient email was available for the delivery test.',
            'message'     => 'Missing valid recipient email.',
            'mode'        => $mode,
            'timestamp'   => current_time('mysql'),
            'email'       => null,
        ], 500);
    }

    if (defined('BFSM_DEBUG') && BFSM_DEBUG) {
        error_log('[BFSM] Mode: ' . $mode);
        error_log('[BFSM] IP: ' . $ip);
        error_log('[BFSM] Attempting to send to: ' . $to);
    }

        $mail_debug = [
            'mailer' => '',
            'host'   => '',
            'error'  => '',
        ];

        $phpmailer_capture = function ($phpmailer) use (&$mail_debug) {
            if (is_object($phpmailer)) {
                $mail_debug['mailer'] = isset($phpmailer->Mailer) ? sanitize_text_field((string) $phpmailer->Mailer) : '';
                $mail_debug['host']   = isset($phpmailer->Host) ? sanitize_text_field((string) $phpmailer->Host) : '';
            }
        };

        $mail_failed_capture = function ($wp_error) use (&$mail_debug) {
            if (is_wp_error($wp_error)) {
                $mail_debug['error'] = sanitize_text_field($wp_error->get_error_message());
            }
        };

        add_action('phpmailer_init', $phpmailer_capture);
        add_action('wp_mail_failed', $mail_failed_capture);

        ob_start();
        $sent = wp_mail($to, $subject, $message, $headers);
        $debug_output = ob_get_clean();

        remove_action('phpmailer_init', $phpmailer_capture);
        remove_action('wp_mail_failed', $mail_failed_capture);
        remove_filter('wp_mail_from_name', $from_name_filter);

        if (empty($mail_debug['mailer']) && isset($GLOBALS['phpmailer']) && is_object($GLOBALS['phpmailer'])) {
            $mail_debug['mailer'] = isset($GLOBALS['phpmailer']->Mailer) ? sanitize_text_field((string) $GLOBALS['phpmailer']->Mailer) : '';
            $mail_debug['host']   = isset($GLOBALS['phpmailer']->Host) ? sanitize_text_field((string) $GLOBALS['phpmailer']->Host) : '';
        }

        $mailer = strtolower((string) $mail_debug['mailer']);
        $wp_mail_smtp_mailer = '';
        $wp_mail_smtp_active = function_exists('wp_mail_smtp') || class_exists('WPMailSMTP\\WP');
        $fluent_smtp_mailer = '';
        $fluent_smtp_simulation = false;
        $fluent_smtp_active = function_exists('fluentMail') || function_exists('fluentMailGetSettings') || defined('FLUENTMAIL_PLUGIN_PATH') || class_exists('FluentMail\\App\\App');

        if ($wp_mail_smtp_active) {
            $wp_mail_smtp_options = get_option('wp_mail_smtp', []);
            if (is_array($wp_mail_smtp_options) && isset($wp_mail_smtp_options['mail']['mailer'])) {
                $wp_mail_smtp_mailer = strtolower(sanitize_key((string) $wp_mail_smtp_options['mail']['mailer']));
            }
        }

        if ($fluent_smtp_active) {
            if (function_exists('fluentMailGetSettings')) {
                $fluent_settings = fluentMailGetSettings([], false);
            } else {
                $fluent_settings = get_option('fluentmail-settings', []);
            }

            if (is_array($fluent_settings)) {
                $fluent_smtp_simulation = (
                    isset($fluent_settings['misc']['simulate_emails']) &&
                    $fluent_settings['misc']['simulate_emails'] === 'yes'
                ) || (defined('FLUENTMAIL_SIMULATE_EMAILS') && FLUENTMAIL_SIMULATE_EMAILS);

                $fluent_connection = [];
                if (
                    isset($fluent_settings['misc']['default_connection'], $fluent_settings['connections'][$fluent_settings['misc']['default_connection']]) &&
                    is_array($fluent_settings['connections'][$fluent_settings['misc']['default_connection']])
                ) {
                    $fluent_connection = $fluent_settings['connections'][$fluent_settings['misc']['default_connection']];
                } elseif (!empty($fluent_settings['connections']) && is_array($fluent_settings['connections'])) {
                    $fluent_connection = reset($fluent_settings['connections']);
                }

                if (is_array($fluent_connection) && isset($fluent_connection['provider_settings']['provider'])) {
                    $fluent_smtp_mailer = strtolower(sanitize_key((string) $fluent_connection['provider_settings']['provider']));
                }
            }
        }

        $managed_mailers = [
            'smtp',
            'gmail',
            'outlook',
            'mailgun',
            'sendgrid',
            'sendinblue',
            'smtpcom',
            'sendlayer',
            'amazonses',
            'elasticemail',
            'mailjet',
            'mailersend',
            'mandrill',
            'postmark',
            'resend',
            'smtp2go',
            'sparkpost',
            'zoho',
            'ses',
            'pepipost',
            'elasticmail',
            'tosend',
            'cloudflare',
        ];
        $smtp_confirmed = ($mailer === 'smtp');
        $managed_transport_confirmed = $smtp_confirmed || (
            $wp_mail_smtp_active &&
            in_array($wp_mail_smtp_mailer, $managed_mailers, true) &&
            $wp_mail_smtp_mailer !== 'mail'
        ) || (
            $fluent_smtp_active &&
            !$fluent_smtp_simulation &&
            $fluent_smtp_mailer !== 'mail'
        );

        if (!$sent) {
            $status = 'fail';
            $http   = 500;
            $message_text = 'wp_mail() returned false';
        } elseif ($fluent_smtp_simulation) {
            $status = 'fail';
            $http   = 500;
            $message_text = 'FluentSMTP simulation mode is enabled, so external delivery was not confirmed.';
        } elseif ($managed_transport_confirmed) {
            $status = 'ok';
            $http   = 200;
            $message_text = $smtp_confirmed ? 'SMTP transport confirmed.' : 'Managed mailer transport confirmed.';
        } elseif (!$smtp_confirmed) {
            $status = 'ok';
            $http   = 200;
            $message_text = 'Email was accepted by WordPress. SMTP transport was not confirmed.';
        }

        return bfsmtp_monitor_rest_response([
            'status'          => $status,
            'email_sent'      => (bool) $sent,
            'smtp_confirmed'  => $managed_transport_confirmed,
            'delivery_method' => $wp_mail_smtp_mailer ? 'wp-mail-smtp:' . $wp_mail_smtp_mailer : ($fluent_smtp_mailer ? 'fluent-smtp:' . $fluent_smtp_mailer : $mail_debug['mailer']),
            'smtp_host'       => $mail_debug['host'],
            'debug_check'     => $debug_output ?: ($mail_debug['error'] ?: $message_text),
            'message'         => $message_text,
            'mode'            => $mode,
            'timestamp'       => current_time('mysql'),
            'email'           => $to,
        ], $http);
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
