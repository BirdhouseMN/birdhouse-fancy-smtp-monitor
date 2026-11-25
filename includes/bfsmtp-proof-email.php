<?php
if (!defined('ABSPATH')) exit;

const BFSMTP_PROOF_WORDMARK = '<strong id="bfsm-proof-wordmark">BIRDHOUSE</strong>';

/** Attach the logo in memory so API mailers can preserve the inline Content-ID. */
function bfsmtp_embed_proof_logo($mailer) {
    $path = dirname(__DIR__) . '/assets/birdhouse-logo-inverted.png';
    if (!method_exists($mailer, 'addStringEmbeddedImage')) {
        return;
    }

    $image = @file_get_contents($path);
    if ($image === false || $image === '') {
        return;
    }

    $content_id = 'bfsmtp-proof-logo.png';
    try {
        if (!$mailer->addStringEmbeddedImage($image, $content_id, 'birdhouse-logo.png', 'base64', 'image/png')) {
            return;
        }
    } catch (\PHPMailer\PHPMailer\Exception $exception) {
        // Keep the wordmark when the active mailer cannot add the inline image.
        return;
    }

    $logo = '<img src="cid:' . $content_id . '" width="120" alt="Birdhouse Web Design" style="display:block;width:120px;max-width:100%;height:auto;border:0">';
    $mailer->Body = str_replace(BFSMTP_PROOF_WORDMARK, $logo, $mailer->Body);
}

/** Presentation only. The site's configured WordPress mail transport sends the proof. */
function bfsmtp_proof_parts() {
    $url = home_url('/');
    $host = (string) wp_parse_url($url, PHP_URL_HOST);
    $identity = sanitize_text_field($host !== '' ? $host : 'Child website');
    $time = current_time('mysql');
    $plain = "MANUAL TEST: Sent directly by this website\nWebsite: $url\nCreated: $time (website time)\n\nThis proof message was sent by this website through its configured WordPress email service. It was not sent by Birdhouse Manager.\n\nReceiving this message confirms delivery to this mailbox. The manager sends a separate test-result notification. No action is needed.\n\nBirdhouse Email Health";
    ob_start(); ?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body bgcolor="#ffffff" style="margin:0;padding:0;background:#ffffff;font-family:Arial,Helvetica,sans-serif">
<div style="display:none;max-height:0;overflow:hidden;opacity:0"><?php echo esc_html('Direct website proof from ' . $identity . ', separate from the manager result.'); ?></div>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" bgcolor="#ffffff"><tr><td align="center" style="padding:28px 12px"><table role="presentation" width="600" cellspacing="0" cellpadding="0" bgcolor="#202a31" style="width:100%;max-width:600px;table-layout:fixed;background:#202a31;border:1px solid #3a4850;border-radius:12px;color:#f3f6f7"><tr><td style="padding:26px 24px">
<?php echo BFSMTP_PROOF_WORDMARK; ?>
<p style="margin:20px 0 16px;font-size:11px;letter-spacing:1.5px;color:#b8c5cb">EMAIL HEALTH &middot; WEBSITE PROOF</p><span style="display:inline-block;padding:7px 11px;background:#228354;border-radius:5px;color:#ffffff;font-size:12px;font-weight:bold">MANUAL TEST MESSAGE</span>
<h1 style="margin:17px 0 14px;font-size:26px;line-height:1.25;color:#f3f6f7">Sent directly by this website</h1><p style="margin:0 0 18px;font-size:22px;line-height:1.4;overflow-wrap:anywhere;word-break:break-word"><a href="<?php echo esc_url($url, ['http','https']); ?>" style="color:#ffa17b;text-decoration:none"><?php echo esc_html($identity); ?></a></p>
<p style="font-size:15px;line-height:1.65">This proof message was sent by this website through its configured WordPress email service. It was not sent by Birdhouse Manager.</p><p style="font-size:15px;line-height:1.65">Receiving this message confirms delivery to this mailbox. The manager sends a separate test-result notification. No action is needed.</p><p style="margin:20px 0 0;font-size:13px;color:#b8c5cb">Created: <?php echo esc_html($time); ?> (website time)</p></td></tr></table><table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:100%;max-width:600px"><tr><td style="padding:18px 6px;font-size:12px;line-height:1.7;color:#667382">Website: <?php echo esc_html($url); ?><br>This message tests the website's email service. It does not verify every form or guarantee delivery to other recipients.</td></tr></table></td></tr></table></body></html>
<?php
    return ['identity'=>$identity, 'subject'=>'[BFSM Manual] ' . $identity . ' - Website email proof', 'html'=>(string) ob_get_clean(), 'plain'=>$plain];
}
