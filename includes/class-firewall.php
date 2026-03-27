<?php
if (!defined('ABSPATH')) exit;

class Linzi_Firewall {

    private $options;

    public function init() {
        $this->options = LinziContinue::get_options();
        if (empty($this->options['firewall_enabled'])) return;

        // Don't run if tables haven't been created yet (first activation)
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_firewall_log';
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table}'") !== $table) return;

        // Run firewall checks early
        $this->check_ip_blocked();
        $this->check_request();
    }

    private function get_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // X-Forwarded-For can contain multiple IPs
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    private function check_ip_blocked() {
        $ip = $this->get_client_ip();

        // Check whitelist first
        if (in_array($ip, $this->options['whitelisted_ips'] ?? [])) {
            return;
        }

        // Check permanent block list
        if (in_array($ip, $this->options['blocked_ips'] ?? [])) {
            $this->block_request($ip, 'ip_blacklist', 'IP is permanently blocked');
        }

        // Check temporary lockouts
        global $wpdb;
        $lockout = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}linzi_lockouts
             WHERE ip_address = %s AND (expires_at > NOW() OR permanent = 1)",
            $ip
        ));

        if ($lockout) {
            $this->block_request($ip, 'ip_lockout', 'IP is locked out: ' . $lockout->reason);
        }
    }

    private function check_request() {
        $ip = $this->get_client_ip();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
        $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';

        // Combine all request data for scanning
        $request_data = $uri . ' ' . $query_string;

        // Add POST data for POST requests
        if ($method === 'POST' && !empty($_POST)) {
            $request_data .= ' ' . http_build_query($_POST);
        }

        // === RULE 1: SQL Injection Detection ===
        $sql_patterns = [
            '/(?:union\s+(?:all\s+)?select)/i',
            '/(?:select\s+.*\s+from\s+.*(?:where|having|order|group|limit))/i',
            '/(?:insert\s+into\s+.*values)/i',
            '/(?:update\s+.*\s+set\s+)/i',
            '/(?:delete\s+from)/i',
            '/(?:drop\s+(?:table|database|column))/i',
            '/(?:(?:--|#|\/\*)\s*$)/m', // SQL comments at end of line
            '/(?:benchmark\s*\()/i',
            '/(?:sleep\s*\(\s*\d)/i',
            '/(?:load_file\s*\()/i',
            '/(?:into\s+(?:out|dump)file)/i',
            '/(?:0x[0-9a-f]{8,})/i', // Long hex strings
        ];

        foreach ($sql_patterns as $pattern) {
            if (preg_match($pattern, $request_data)) {
                $this->log_and_block($ip, $uri, $method, 'sql_injection', 'SQL injection attempt detected');
                return;
            }
        }

        // === RULE 2: XSS Detection ===
        $xss_patterns = [
            '/<script[\s>]/i',
            '/javascript\s*:/i',
            '/on(?:load|error|click|mouseover|focus|blur|submit|change|keyup|keydown)\s*=/i',
            '/<iframe/i',
            '/<object/i',
            '/<embed/i',
            '/\bvbscript\s*:/i',
            '/expression\s*\(/i',
            '/url\s*\(\s*javascript/i',
        ];

        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $request_data)) {
                $this->log_and_block($ip, $uri, $method, 'xss', 'XSS attempt detected');
                return;
            }
        }

        // === RULE 3: Path Traversal Detection ===
        $traversal_patterns = [
            '/\.\.\//i',
            '/\.\.\\\\/',
            '/%2e%2e%2f/i',
            '/%2e%2e\//i',
            '/\.%2e\//i',
            '/%252e%252e/i',
            '/etc\/passwd/i',
            '/proc\/self/i',
            '/wp-config\.php/i', // Direct access attempt to wp-config
        ];

        // Only check URI for traversal (not POST data which might legitimately contain paths)
        foreach ($traversal_patterns as $pattern) {
            if (preg_match($pattern, $uri . ' ' . $query_string)) {
                $this->log_and_block($ip, $uri, $method, 'path_traversal', 'Path traversal attempt detected');
                return;
            }
        }

        // === RULE 4: Remote Code Execution ===
        $rce_patterns = [
            '/(?:cmd|command)\s*=\s*(?:ls|cat|wget|curl|nc|bash|sh|python|perl|ruby|php)/i',
            '/(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i',
            '/phpinfo\s*\(\s*\)/i',
        ];

        foreach ($rce_patterns as $pattern) {
            if (preg_match($pattern, $request_data)) {
                $this->log_and_block($ip, $uri, $method, 'rce', 'Remote code execution attempt');
                return;
            }
        }

        // === RULE 5: File Inclusion Detection ===
        $fi_patterns = [
            '/(?:include|require)(?:_once)?\s*\(\s*[\'"]?(?:https?|ftp|php|data|expect|input|filter)/i',
            '/(?:php:\/\/(?:input|filter))/i',
            '/(?:data:\/\/)/i',
            '/(?:expect:\/\/)/i',
        ];

        foreach ($fi_patterns as $pattern) {
            if (preg_match($pattern, $request_data)) {
                $this->log_and_block($ip, $uri, $method, 'file_inclusion', 'File inclusion attempt');
                return;
            }
        }

        // === RULE 6: Sensitive File Access ===
        $sensitive_files = [
            '/\.env(\.|$)/i',
            '/\.git\//i',
            '/\.svn\//i',
            '/\.htpasswd/i',
            '/wp-config\.bak/i',
            '/\.sql(\.|$)/i',
            '/\.log(\.|$)/i',
            '/phpunit\.xml/i',
            '/composer\.(json|lock)/i',
            '/\.DS_Store/i',
            '/Thumbs\.db/i',
            '/debug\.log/i',
        ];

        foreach ($sensitive_files as $pattern) {
            if (preg_match($pattern, $uri)) {
                $this->log_and_block($ip, $uri, $method, 'sensitive_access', 'Sensitive file access attempt');
                return;
            }
        }

        // === RULE 7: Bad Bot Detection ===
        $bad_bots = [
            '/(?:sqlmap|nikto|dirbuster|gobuster|nmap|masscan|acunetix|nessus|openvas)/i',
            '/(?:havij|pangolin|w3af|commix|wpscan)/i', // WPScan is useful but risky from unknown IPs
            '/(?:python-requests|python-urllib|Go-http-client|Java\/\d)/i',
            '/^$/i', // Empty user agent
        ];

        foreach ($bad_bots as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                // Don't block legitimate tools, just log
                $this->log_request($ip, $uri, $method, 'bad_bot', 'logged');
                break;
            }
        }

        // === RULE 8: XML-RPC Protection ===
        if ($this->options['disable_xmlrpc'] ?? false) {
            if (strpos($uri, '/xmlrpc.php') !== false) {
                $this->log_and_block($ip, $uri, $method, 'xmlrpc_blocked', 'XML-RPC access blocked');
                return;
            }
        }

        // === RULE 9: Rate Limiting ===
        $this->check_rate_limit($ip);

        // === RULE 10: POST to non-standard PHP files ===
        if ($method === 'POST' && preg_match('/\.php$/i', $uri)) {
            $allowed_post_targets = [
                '/wp-login.php', '/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php',
                '/wp-cron.php', '/wp-comments-post.php', '/wp-admin/options.php',
                '/wp-admin/post.php', '/wp-admin/edit.php', '/wp-admin/upload.php',
                '/wp-admin/profile.php', '/wp-admin/user-edit.php',
                '/wp-admin/users.php', '/wp-admin/plugins.php', '/wp-admin/themes.php',
                '/wp-json/', // REST API
            ];

            $is_allowed = false;
            foreach ($allowed_post_targets as $target) {
                if (strpos($uri, $target) !== false) {
                    $is_allowed = true;
                    break;
                }
            }

            // Allow admin-area POSTs
            if (strpos($uri, '/wp-admin/') === 0) {
                $is_allowed = true;
            }

            if (!$is_allowed) {
                $this->log_request($ip, $uri, $method, 'suspicious_post', 'logged');
            }
        }
    }

    private function check_rate_limit($ip) {
        global $wpdb;

        // Count requests in last minute
        $count = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_firewall_log
             WHERE ip_address = %s AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
            $ip
        ));

        // More than 120 requests per minute = suspicious
        if ($count > 120) {
            // Auto-lockout for 30 minutes
            $wpdb->insert($wpdb->prefix . 'linzi_lockouts', [
                'ip_address' => $ip,
                'reason'     => 'Rate limit exceeded (' . $count . ' requests/minute)',
                'locked_at'  => current_time('mysql'),
                'expires_at' => gmdate('Y-m-d H:i:s', time() + 1800),
            ]);

            $this->block_request($ip, 'rate_limit', 'Rate limit exceeded');
        }
    }

    private function log_and_block($ip, $uri, $method, $rule, $description) {
        $this->log_request($ip, $uri, $method, $rule, 'blocked');

        // Log to activity log
        if (class_exists('Linzi_Activity_Log')) {
            $log = new Linzi_Activity_Log();
            $log->log('firewall_block', 'warning', $description, [
                'ip'     => $ip,
                'uri'    => $uri,
                'method' => $method,
                'rule'   => $rule,
            ]);
        }

        $this->block_request($ip, $rule, $description);
    }

    private function log_request($ip, $uri, $method, $rule, $action) {
        global $wpdb;
        $wpdb->insert($wpdb->prefix . 'linzi_firewall_log', [
            'ip_address'     => $ip,
            'request_uri'    => substr($uri, 0, 2000),
            'request_method' => $method,
            'rule_matched'   => $rule,
            'action_taken'   => $action,
            'created_at'     => current_time('mysql'),
        ]);
    }

    private function block_request($ip, $rule, $reason) {
        status_header(403);
        header('X-Linzi-Block: ' . $rule);

        // Return a generic 403 page (don't reveal security details)
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
        echo '<h1>403 Forbidden</h1>';
        echo '<p>Access denied.</p>';
        echo '</body></html>';
        exit;
    }

    public function get_blocked_count() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_firewall_log WHERE action_taken = 'blocked'"
        );
    }

    public function get_blocked_today() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_firewall_log
             WHERE action_taken = 'blocked' AND created_at >= CURDATE()"
        );
    }

    public function get_top_blocked_ips($limit = 10) {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare(
            "SELECT ip_address, COUNT(*) as block_count, MAX(created_at) as last_blocked
             FROM {$wpdb->prefix}linzi_firewall_log
             WHERE action_taken = 'blocked'
             GROUP BY ip_address
             ORDER BY block_count DESC
             LIMIT %d",
            $limit
        ), ARRAY_A);
    }

    public function get_attack_types($days = 7) {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare(
            "SELECT rule_matched, COUNT(*) as count
             FROM {$wpdb->prefix}linzi_firewall_log
             WHERE action_taken = 'blocked' AND created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
             GROUP BY rule_matched
             ORDER BY count DESC",
            $days
        ), ARRAY_A);
    }
}
