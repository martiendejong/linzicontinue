<?php
/**
 * Dependency-free signature test for the detections ported into class-scanner.php
 * from jengo-system-private/tools/wp-malware-scan-{ftp,rest}.py (JengoWork task 755).
 *
 * No PHPUnit/Composer in this repo - run directly: php tests/test-scanner-signatures.php
 * Exercises the REAL shipped Linzi_Scanner methods (private helpers via Reflection),
 * not a re-implementation of their regexes.
 */

error_reporting(E_ALL & ~E_DEPRECATED);

// --- minimal WP stubs, just enough to construct Linzi_Scanner and drive the new
// self-probe/homepage-scan wrappers without a real WordPress install ---
define('ABSPATH', __DIR__ . '/fixtures/');
define('LINZI_PLUGIN_DIR', dirname(__DIR__) . '/');

class WP_Error {}

$GLOBALS['__linzi_test_http'] = [];

// Keys are matched as URL prefixes (scan_homepage_html() appends a cache-busting
// timestamp query string, so an exact-match lookup wouldn't work for that case).
function wp_remote_get($url, $args = []) {
    foreach ($GLOBALS['__linzi_test_http'] as $prefix => $response) {
        if (strpos($url, $prefix) === 0) {
            return $response;
        }
    }
    return ['response' => ['code' => 404], 'body' => ''];
}
function is_wp_error($thing) { return $thing instanceof WP_Error; }
function wp_remote_retrieve_response_code($response) { return $response['response']['code'] ?? 0; }
function wp_remote_retrieve_body($response) { return $response['body'] ?? ''; }
function home_url($path = '') { return 'https://example-test-site.local' . $path; }

require_once dirname(__DIR__) . '/includes/class-scanner.php';

$pass = 0;
$fail = 0;
$failures = [];

function check($label, $condition) {
    global $pass, $fail, $failures;
    if ($condition) {
        $pass++;
    } else {
        $fail++;
        $failures[] = $label;
    }
}

$scanner = new Linzi_Scanner();

// ============================================================
// 1. Filename-based known-shell detection
// ============================================================
$shell_names = ['worksec.php', 'filefuns.php', 'wp-geren.php', 'wp-sx.php', 'wp-log1n.php',
                'mah.php', 'motu.php', 'theme-editor-4f9a.php', 'adminerXYZ.php',
                'alfa3.php', 'wsoshell.php', 'c99shell.php', 'r57v2.php'];
foreach ($shell_names as $name) {
    $results = ['threats' => [], 'files_scanned' => 0];
    $handled = $scanner->check_filename_based_threats($name, '/tmp/' . $name, $results);
    check("shell-name detected: $name", $handled === true && count($results['threats']) === 1 && $results['threats'][0]['signature'] === 'SHELL_NAME');
}

// False positives: real WP-core filenames must NOT trigger shell-name detection
$core_names = ['index.php', 'wp-settings.php', 'wp-load.php', 'class-wp-editor.php', 'functions.php'];
foreach ($core_names as $name) {
    $results = ['threats' => [], 'files_scanned' => 0];
    $handled = $scanner->check_filename_based_threats($name, '/tmp/' . $name, $results);
    check("WP-core filename NOT flagged: $name", $handled === false && count($results['threats']) === 0);
}

// ============================================================
// 2. Hex-extension disguise
// ============================================================
$hex_ext_names = ['shell.php4a9f', 'config.phpDEAD', 'x.php1234abcd'];
foreach ($hex_ext_names as $name) {
    $results = ['threats' => [], 'files_scanned' => 0];
    $handled = $scanner->check_filename_based_threats($name, '/tmp/' . $name, $results);
    check("hex-extension detected: $name", $handled === true && $results['threats'][0]['signature'] === 'HEX_EXT');
}

// False positives: plain .php files must not match the hex-extension regex
foreach (['index.php', 'wp-config.php', 'my-plugin-v2.php'] as $name) {
    $results = ['threats' => [], 'files_scanned' => 0];
    $handled = $scanner->check_filename_based_threats($name, '/tmp/' . $name, $results);
    check("plain .php NOT flagged as hex-ext: $name", $handled === false);
}

// ============================================================
// 3. Malicious .htaccess content
// ============================================================
$tmp_htaccess = sys_get_temp_dir() . '/linzi-test-htaccess-' . uniqid();
file_put_contents($tmp_htaccess, "RewriteEngine On\nRewriteRule ^filefuns\\.php$ - [L]\n");
$results = ['threats' => [], 'files_scanned' => 0];
$handled = $scanner->check_filename_based_threats('.htaccess', $tmp_htaccess, $results);
check('malicious .htaccess detected', $handled === true && count($results['threats']) === 1 && $results['threats'][0]['signature'] === 'HTACCESS_MAL');
unlink($tmp_htaccess);

// False positive: a normal WordPress .htaccess (no shell references) must not be flagged
$tmp_clean_htaccess = sys_get_temp_dir() . '/linzi-test-htaccess-clean-' . uniqid();
file_put_contents($tmp_clean_htaccess, "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\n</IfModule>\n# END WordPress\n");
$results = ['threats' => [], 'files_scanned' => 0];
$handled = $scanner->check_filename_based_threats('.htaccess', $tmp_clean_htaccess, $results);
check('clean WP .htaccess NOT flagged', $handled === true && count($results['threats']) === 0);
unlink($tmp_clean_htaccess);

// ============================================================
// 4. Suspicious hex/campaign-named directories
// ============================================================
$susp_dirs = ['4f9a2b', 'ab12', 'wp-includes88', 'cgi-bin88', 'assets7c3d1', 'boss2026yt9a1b2'];
foreach ($susp_dirs as $dir) {
    $results = ['threats' => []];
    $scanner->check_suspicious_directory_name($dir, '/tmp/' . $dir, $results);
    check("suspicious directory detected: $dir", count($results['threats']) === 1 && $results['threats'][0]['signature'] === 'SUSP_DIR');
}

// False positives: normal plugin/theme directory names must not be flagged
$normal_dirs = ['woocommerce', 'akismet', 'twentytwentyfour', 'assets', 'js', 'includes'];
foreach ($normal_dirs as $dir) {
    $results = ['threats' => []];
    $scanner->check_suspicious_directory_name($dir, '/tmp/' . $dir, $results);
    check("normal directory NOT flagged: $dir", count($results['threats']) === 0);
}

// ============================================================
// 5. Self-probe of known shell URLs
// ============================================================
$paths = $scanner->get_known_shell_probe_paths();
check('probe path list is non-empty', count($paths) > 0);

$threat = $scanner->evaluate_shell_probe_response('/worksec.php', 200);
check('probe 200 response flagged', $threat !== null && $threat['signature'] === 'SELF_PROBE');

$threat = $scanner->evaluate_shell_probe_response('/worksec.php', 404);
check('probe 404 response NOT flagged', $threat === null);

// End-to-end through the real wrapper (stubbed wp_remote_get)
$GLOBALS['__linzi_test_http'] = [
    'https://example-test-site.local/worksec.php' => ['response' => ['code' => 200], 'body' => 'shell'],
];
$live_threats = $scanner->self_probe_shell_urls();
check('self_probe_shell_urls() end-to-end finds the live shell', count($live_threats) === 1 && $live_threats[0]['file_path'] === '/worksec.php');

// ============================================================
// 6. Homepage HTML injection scan
// ============================================================
$malicious_html = '<html><body><script>eval(base64_decode("ZXZpbA=="))</script></body></html>';
$threats = $scanner->evaluate_homepage_html($malicious_html);
check('malicious homepage HTML flagged', count($threats) >= 1);

$clean_html = '<html><head><title>My Site</title></head><body><h1>Welcome</h1><p>Just a normal WordPress homepage.</p></body></html>';
$threats = $scanner->evaluate_homepage_html($clean_html);
check('clean homepage HTML NOT flagged', count($threats) === 0);

// End-to-end through the real wrapper (stubbed wp_remote_get, prefix-matched because
// scan_homepage_html() appends a cache-busting timestamp query string)
$GLOBALS['__linzi_test_http'] = [
    'https://example-test-site.local/?linzi_scan=' => [
        'response' => ['code' => 200],
        'body'     => '<script>document.write(unescape("%3C"))</script>',
    ],
];
$threats = $scanner->scan_homepage_html();
check('scan_homepage_html() end-to-end finds the injected script', count($threats) >= 1);

// ============================================================
echo "\n=== RESULTS: $pass passed, $fail failed ===\n";
if ($fail > 0) {
    echo "FAILED:\n";
    foreach ($failures as $f) {
        echo "  - $f\n";
    }
    exit(1);
}
exit(0);
