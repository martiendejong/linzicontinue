<?php
if (!defined('ABSPATH')) exit;

/**
 * MU-Plugins Monitor - The #1 persistence mechanism for WordPress malware.
 *
 * Based on real-world forensics (martiendejong.nl breach, 2026-03-26):
 * - mu-plugins auto-load on EVERY page request
 * - They survive plugin deactivation/deletion
 * - They don't appear in the standard plugins list
 * - They are the FIRST place to check when a site is compromised
 * - Attackers use them to create admin accounts, inject backdoors, maintain persistence
 *
 * This monitor runs every 5 minutes and alerts on ANY unauthorized changes.
 */
class Linzi_MU_Monitor {

    private $mu_dir;

    public function __construct() {
        $this->mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
    }

    public function take_snapshot() {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_mu_registry';

        if (!is_dir($this->mu_dir)) {
            return;
        }

        $files = glob($this->mu_dir . '/*.php');
        if (!$files) return;

        foreach ($files as $file) {
            $filename = basename($file);
            $hash = hash_file('sha256', $file);
            $size = filesize($file);

            $existing = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table WHERE file_name = %s",
                $filename
            ));

            if ($existing) {
                $wpdb->update($table, [
                    'file_hash'    => $hash,
                    'file_size'    => $size,
                    'last_checked' => current_time('mysql'),
                ], ['file_name' => $filename]);
            } else {
                $wpdb->insert($table, [
                    'file_name'    => $filename,
                    'file_hash'    => $hash,
                    'file_size'    => $size,
                    'is_approved'  => 0, // New files start unapproved
                    'first_seen'   => current_time('mysql'),
                    'last_checked' => current_time('mysql'),
                ]);
            }
        }
    }

    public function check_mu_plugins() {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_mu_registry';

        $options = LinziContinue::get_options();
        if (empty($options['mu_monitoring'])) return;

        $alerts = [];

        // 1. Check for NEW mu-plugin files (not in registry)
        if (is_dir($this->mu_dir)) {
            $current_files = glob($this->mu_dir . '/*.php');
            if ($current_files) {
                foreach ($current_files as $file) {
                    $filename = basename($file);
                    $exists = $wpdb->get_var($wpdb->prepare(
                        "SELECT COUNT(*) FROM $table WHERE file_name = %s",
                        $filename
                    ));

                    if (!$exists) {
                        // NEW mu-plugin detected!
                        $content = file_get_contents($file);
                        $hash = hash('sha256', $content);

                        // Analyze the file for malicious patterns
                        $analysis = $this->analyze_mu_plugin($file, $content);

                        $alerts[] = [
                            'type'     => 'new_mu_plugin',
                            'severity' => $analysis['is_suspicious'] ? 'critical' : 'warning',
                            'file'     => $filename,
                            'path'     => $file,
                            'hash'     => $hash,
                            'size'     => filesize($file),
                            'analysis' => $analysis,
                            'message'  => sprintf(
                                'New mu-plugin detected: %s (%s) - %s',
                                $filename,
                                size_format(filesize($file)),
                                $analysis['is_suspicious'] ? 'SUSPICIOUS CONTENT' : 'needs review'
                            ),
                        ];

                        // Register it (unapproved)
                        $wpdb->insert($table, [
                            'file_name'    => $filename,
                            'file_hash'    => $hash,
                            'file_size'    => filesize($file),
                            'is_approved'  => 0,
                            'first_seen'   => current_time('mysql'),
                            'last_checked' => current_time('mysql'),
                        ]);
                    }
                }
            }
        }

        // 2. Check for MODIFIED mu-plugin files
        $registered = $wpdb->get_results("SELECT * FROM $table", ARRAY_A);
        foreach ($registered as $record) {
            $filepath = $this->mu_dir . '/' . $record['file_name'];

            if (!file_exists($filepath)) {
                // File was deleted (could be cleanup or attacker covering tracks)
                $alerts[] = [
                    'type'     => 'deleted_mu_plugin',
                    'severity' => 'warning',
                    'file'     => $record['file_name'],
                    'message'  => sprintf(
                        'MU-plugin deleted: %s (was %s, first seen: %s)',
                        $record['file_name'],
                        $record['is_approved'] ? 'approved' : 'unapproved',
                        $record['first_seen']
                    ),
                ];
                continue;
            }

            $current_hash = hash_file('sha256', $filepath);
            if ($current_hash !== $record['file_hash']) {
                $content = file_get_contents($filepath);
                $analysis = $this->analyze_mu_plugin($filepath, $content);

                $alerts[] = [
                    'type'     => 'modified_mu_plugin',
                    'severity' => $analysis['is_suspicious'] ? 'critical' : 'high',
                    'file'     => $record['file_name'],
                    'path'     => $filepath,
                    'old_hash' => $record['file_hash'],
                    'new_hash' => $current_hash,
                    'analysis' => $analysis,
                    'message'  => sprintf(
                        'MU-plugin modified: %s - %s',
                        $record['file_name'],
                        $analysis['is_suspicious'] ? 'CONTAINS SUSPICIOUS CODE' : 'hash changed'
                    ),
                ];

                // Update hash
                $wpdb->update($table, [
                    'file_hash'    => $current_hash,
                    'file_size'    => filesize($filepath),
                    'is_approved'  => 0, // Reset approval on modification
                    'last_checked' => current_time('mysql'),
                ], ['file_name' => $record['file_name']]);
            } else {
                // Update last checked
                $wpdb->update($table, [
                    'last_checked' => current_time('mysql'),
                ], ['file_name' => $record['file_name']]);
            }
        }

        // 3. Check for mu-plugins directory creation (shouldn't exist on clean sites usually)
        if (is_dir($this->mu_dir)) {
            $file_count = count(glob($this->mu_dir . '/*'));
            if ($file_count === 0) {
                // Empty mu-plugins dir is fine
            }
        }

        // Process alerts
        if (!empty($alerts)) {
            $this->process_alerts($alerts);
        }

        update_option('linzi_last_mu_check', current_time('mysql'));

        return $alerts;
    }

    private function analyze_mu_plugin($filepath, $content) {
        $analysis = [
            'is_suspicious' => false,
            'risk_level'    => 0,
            'findings'      => [],
            'plugin_header' => $this->extract_plugin_header($content),
        ];

        // Check for common backdoor patterns
        $dangerous_patterns = [
            ['pattern' => '/\beval\s*\(/i', 'name' => 'eval() usage', 'risk' => 30],
            ['pattern' => '/\bbase64_decode\s*\(/i', 'name' => 'base64_decode()', 'risk' => 20],
            ['pattern' => '/\bsystem\s*\(/i', 'name' => 'system() call', 'risk' => 40],
            ['pattern' => '/\bexec\s*\(/i', 'name' => 'exec() call', 'risk' => 40],
            ['pattern' => '/\bshell_exec\s*\(/i', 'name' => 'shell_exec() call', 'risk' => 40],
            ['pattern' => '/\bpassthru\s*\(/i', 'name' => 'passthru() call', 'risk' => 40],
            ['pattern' => '/\bpopen\s*\(/i', 'name' => 'popen() call', 'risk' => 30],
            ['pattern' => '/\bproc_open\s*\(/i', 'name' => 'proc_open() call', 'risk' => 30],
            ['pattern' => '/wp_insert_user/i', 'name' => 'User creation code', 'risk' => 50],
            ['pattern' => '/wp_set_current_user\s*\(\s*1/i', 'name' => 'Auth bypass (user ID 1)', 'risk' => 60],
            ['pattern' => '/wp_set_auth_cookie/i', 'name' => 'Auth cookie manipulation', 'risk' => 50],
            ['pattern' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', 'name' => 'Direct superglobal access', 'risk' => 15],
            ['pattern' => '/file_put_contents\s*\(.*\.php/i', 'name' => 'PHP file writing', 'risk' => 40],
            ['pattern' => '/move_uploaded_file/i', 'name' => 'File upload handler', 'risk' => 30],
            ['pattern' => '/\bcurl_exec\s*\(/i', 'name' => 'External HTTP request', 'risk' => 10],
            ['pattern' => '/\bfsockopen\s*\(/i', 'name' => 'Raw socket connection', 'risk' => 25],
            ['pattern' => '/\$\w+\s*\(\s*\$\w+\s*\)/i', 'name' => 'Variable function call', 'risk' => 25],
            ['pattern' => '/gzinflate\s*\(\s*base64/i', 'name' => 'Compressed+encoded payload', 'risk' => 50],
            ['pattern' => '/str_rot13\s*\(/i', 'name' => 'ROT13 obfuscation', 'risk' => 30],
            ['pattern' => '/assert\s*\(\s*\$/i', 'name' => 'assert() with variable', 'risk' => 40],
            ['pattern' => '/create_function\s*\(/i', 'name' => 'create_function() (deprecated)', 'risk' => 35],
        ];

        foreach ($dangerous_patterns as $check) {
            if (preg_match($check['pattern'], $content)) {
                $analysis['findings'][] = $check['name'];
                $analysis['risk_level'] += $check['risk'];
            }
        }

        // Check if file has valid WordPress plugin header
        if (empty($analysis['plugin_header']['name'])) {
            $analysis['findings'][] = 'Missing plugin header (not a legitimate mu-plugin)';
            $analysis['risk_level'] += 20;
        }

        // Check file size (legitimate mu-plugins are usually small)
        $size = filesize($filepath);
        if ($size > 500 * 1024) { // > 500KB
            $analysis['findings'][] = 'Unusually large mu-plugin (' . size_format($size) . ')';
            $analysis['risk_level'] += 15;
        }

        // Check for obfuscation indicators
        $line_count = substr_count($content, "\n") + 1;
        $avg_line_length = strlen($content) / max(1, $line_count);
        if ($avg_line_length > 500) {
            $analysis['findings'][] = 'Possible code obfuscation (very long lines)';
            $analysis['risk_level'] += 20;
        }

        // Determine if suspicious (risk_level > 40 = suspicious)
        $analysis['is_suspicious'] = $analysis['risk_level'] > 40;
        $analysis['risk_level'] = min(100, $analysis['risk_level']);

        return $analysis;
    }

    private function extract_plugin_header($content) {
        $headers = [
            'name'        => 'Plugin Name',
            'uri'         => 'Plugin URI',
            'version'     => 'Version',
            'description' => 'Description',
            'author'      => 'Author',
        ];

        $result = [];
        foreach ($headers as $key => $header) {
            if (preg_match('/' . preg_quote($header) . ':\s*(.+)/i', $content, $match)) {
                $result[$key] = trim($match[1]);
            }
        }

        return $result;
    }

    private function process_alerts($alerts) {
        $critical = array_filter($alerts, function ($a) {
            return $a['severity'] === 'critical';
        });

        // Log all alerts
        if (class_exists('Linzi_Activity_Log')) {
            $log = new Linzi_Activity_Log();
            foreach ($alerts as $alert) {
                $log->log('mu_plugin_alert', $alert['severity'], $alert['message'], $alert);
            }
        }

        // Store alerts for dashboard
        $existing = get_option('linzi_mu_alerts', []);
        $existing = array_merge($existing, $alerts);
        // Keep last 100 alerts
        $existing = array_slice($existing, -100);
        update_option('linzi_mu_alerts', $existing);

        // Send email for critical alerts
        if (!empty($critical)) {
            $this->send_mu_alert($alerts);
        }
    }

    private function send_mu_alert($alerts) {
        $options = LinziContinue::get_options();
        $email = $options['email_alerts'];
        if (empty($email)) return;

        $critical_count = count(array_filter($alerts, function ($a) {
            return $a['severity'] === 'critical';
        }));

        $subject = sprintf(
            '[Linzi] %s MU-PLUGINS ALERT on %s - %d changes detected',
            $critical_count > 0 ? 'CRITICAL' : 'WARNING',
            get_bloginfo('name'),
            count($alerts)
        );

        $body = sprintf(
            "MU-PLUGINS MONITORING ALERT\n" .
            "===========================\n\n" .
            "Site: %s\n" .
            "Time: %s\n" .
            "Changes detected: %d\n\n" .
            "IMPORTANT: mu-plugins auto-load on EVERY page request and are the\n" .
            "#1 persistence mechanism for WordPress malware. Investigate immediately.\n\n",
            get_site_url(),
            current_time('mysql'),
            count($alerts)
        );

        foreach ($alerts as $alert) {
            $body .= sprintf(
                "[%s] %s\n  %s\n",
                strtoupper($alert['severity']),
                $alert['type'],
                $alert['message']
            );

            if (!empty($alert['analysis']['findings'])) {
                $body .= "  Findings:\n";
                foreach ($alert['analysis']['findings'] as $finding) {
                    $body .= "    - $finding\n";
                }
            }
            $body .= "\n";
        }

        $body .= "Log in to review: " . admin_url('admin.php?page=linzicontinue&tab=mu-plugins') . "\n";

        wp_mail($email, $subject, $body);
    }

    public function approve_mu_plugin($filename) {
        global $wpdb;
        $wpdb->update(
            $wpdb->prefix . 'linzi_mu_registry',
            ['is_approved' => 1],
            ['file_name' => $filename]
        );
    }

    public function get_mu_plugin_count() {
        if (!is_dir($this->mu_dir)) return 0;
        $files = glob($this->mu_dir . '/*.php');
        return $files ? count($files) : 0;
    }

    public function get_mu_plugin_list() {
        global $wpdb;
        return $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}linzi_mu_registry ORDER BY first_seen DESC",
            ARRAY_A
        );
    }

    public function get_unapproved_count() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_mu_registry WHERE is_approved = 0"
        );
    }
}
