<?php
define('ABSPATH', __DIR__ . '/');
$hooks = []; $sends = []; $send_ok = true; $can_embed = true;
function add_action($n,$f,...$args) { $GLOBALS['hooks'][$n][]=$f; }
function add_filter($n,$f,...$args) { add_action($n,$f); }
function remove_action($n,$f,...$args) { $GLOBALS['hooks'][$n]=array_filter($GLOBALS['hooks'][$n]??[],static function($x)use($f){return $x!==$f;}); }
function remove_filter($n,$f,...$args) { remove_action($n,$f); }
function register_activation_hook(...$args) {}
function plugin_dir_path($f) { return __DIR__.'/no-updater-in-unit-tests/'; }
function get_option($k,$default=false) { return ['bfsmtp_site_token'=>'test-only-token','admin_email'=>'test@example.test'][$k]??$default; }
function sanitize_text_field($s) { return trim(strip_tags((string)$s)); }
function sanitize_key($s) { return $s; }
function sanitize_email($s) { return filter_var($s,FILTER_VALIDATE_EMAIL)?$s:''; }
function is_email($s) { return filter_var($s,FILTER_VALIDATE_EMAIL); }
function home_url($s='') { return 'https://americanlandandcapital.com'.$s; }
function wp_parse_url($u,$part) { return parse_url($u,$part); }
function current_time($f) { return '2026-11-22 14:00:00'; }
function esc_html($s) { return htmlspecialchars($s,ENT_QUOTES,'UTF-8'); }
function esc_url($s,...$a) { return htmlspecialchars($s,ENT_QUOTES,'UTF-8'); }
function is_wp_error($e) { return false; }
class WP_REST_Response { public $data,$status; function __construct($d,$s){$this->data=$d;$this->status=$s;} function header(...$args){} }
class Request { public $mode,$token; function __construct($mode,$token='test-only-token'){$this->mode=$mode;$this->token=$token;} function get_header($n){return $this->token;} function get_param($n){return $n==='mode'?$this->mode:($n==='notify'?'test@example.test':'');} }
function get_transient($k){return false;} function set_transient(...$a){}
function wp_mail($to,$subject,$message,$headers) {
    $mailer=new class {
        public $AltBody='',$Body='',$Mailer='smtp',$Host='configured.example',$embedded=[];
        function addStringEmbeddedImage(...$args){
            if (!$GLOBALS['can_embed']) return false;
            $this->embedded[]=$args;
            return true;
        }
    };
    $mailer->Body=$message;
    foreach($GLOBALS['hooks']['phpmailer_init']??[] as $f)$f($mailer);
    $name='Site sender';foreach($GLOBALS['hooks']['wp_mail_from_name']??[] as $f)$name=$f($name);
    $GLOBALS['sends'][]=compact('to','subject','message','headers','mailer','name');
    return $GLOBALS['send_ok'];
}
function check($ok,$message){if(!$ok)throw new Exception($message);}
require dirname(__DIR__).'/birdhouse-fancy-smtp-monitor.php';
$r=bfsmtp_status_check(new Request('manual'));$s=end($sends);
check($r->status===200&&$r->data['email_sent']===true,'Manual send result');
check(strpos($s['subject'],'americanlandandcapital.com')!==false,'Inbox domain missing');
check(strpos($s['name'],'americanlandandcapital.com')!==false,'Sender display identity');
check(strpos($s['message'],'Sent directly by this website')!==false,'Visible source');
check(strpos($s['message'],'It was not sent by Birdhouse Manager')!==false,'Manager distinction');
check(strpos($s['mailer']->AltBody,'Website: https://americanlandandcapital.com/')!==false,'Plain alternative');
$logo_path=dirname(__DIR__).'/assets/birdhouse-logo-inverted.png';
check($s['mailer']->embedded===[[file_get_contents($logo_path),'bfsmtp-proof-logo.png','birdhouse-logo.png','base64','image/png']],'PNG bytes must be embedded inline with the intended Content-ID');
check(strpos($s['mailer']->Body,'src="cid:bfsmtp-proof-logo.png"')!==false,'HTML uses the embedded Content-ID');
$can_embed=false;
bfsmtp_status_check(new Request('manual'));
$fallback=end($sends);
check(strpos($fallback['mailer']->Body,BFSMTP_PROOF_WORDMARK)!==false && strpos($fallback['mailer']->Body,'src="cid:')===false,'Embedding failure keeps the text wordmark');
$can_embed=true;
check($s['headers']===['Content-Type: text/html; charset=UTF-8'],'No sender-address or reply-to override');
check(strpos($s['message'],'test-only-token')===false,'Secret must not appear');
check(empty($hooks['phpmailer_init'])&&empty($hooks['wp_mail_from_name']),'Scoped hooks cleaned');
$r=bfsmtp_status_check(new Request('auto'));$s=end($sends);
check($s['subject']==='[BFSM Probe] Automatic Email Verification','Automatic subject compatibility');
check($s['headers']===['Content-Type: text/plain; charset=UTF-8']&&$s['mailer']->AltBody==='','Automatic mail unchanged');
$send_ok=false;$r=bfsmtp_status_check(new Request('manual'));
check($r->status===500&&$r->data['email_sent']===false,'Failed send must remain failed');
check(empty($hooks['phpmailer_init'])&&empty($hooks['wp_mail_from_name']),'Failed send cleanup');
$count=count($sends);$r=bfsmtp_status_check(new Request('manual','wrong-token'));
check($r->status===403&&count($sends)===$count,'Unauthorized check must never send');
echo "PASS: manual source, branded HTML/plain alternative, unchanged automatic send, failed send and authentication. No emails sent.\n";
