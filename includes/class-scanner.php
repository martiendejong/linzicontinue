<?php
if (!defined('ABSPATH')) exit;

class Linzi_Scanner {

    // Malware signatures - based on real-world breach forensics (martiendejong.nl 2026-03-26)
    private $signatures = [];

    public function __construct() {
        $this->load_signatures();
    }

    private function load_signatures() {
        // Always start with built-in signatures
        $this->signatures = $this->get_builtin_signatures();

        // Merge custom signatures from JSON file if present
        $sig_file = LINZI_PLUGIN_DIR . 'assets/signatures.json';
        if (file_exists($sig_file)) {
            $data = json_decode(file_get_contents($sig_file), true);
            if ($data && !empty($data['custom']) && is_array($data['custom'])) {
                $this->signatures = array_merge($this->signatures, $data['custom']);
            }
        }
    }

    private function get_builtin_signatures() {
        return [
            // === BACKDOOR SHELLS ===
            [
                'id'       => 'SHELL_001',
                'name'     => 'PHP Eval Backdoor',
                'pattern'  => '/\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/i',
                'severity' => 'critical',
                'type'     => 'backdoor',
            ],
            [
                'id'       => 'SHELL_002',
                'name'     => 'PHP System Command Execution',
                'pattern'  => '/\b(system|passthru|exec|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'critical',
                'type'     => 'backdoor',
            ],
            [
                'id'       => 'SHELL_003',
                'name'     => 'PHP Assert Backdoor',
                'pattern'  => '/\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => 'critical',
                'type'     => 'backdoor',
            ],
            [
                'id'       => 'SHELL_004',
                'name'     => 'PHP Create Function Backdoor',
                'pattern'  => '/\bcreate_function\s*\(\s*[\'\"]\s*[\'\"],\s*\$_(GET|POST|REQUEST)/i',
                'severity' => 'critical',
                'type'     => 'backdoor',
            ],
            [
                'id'       => 'SHELL_005',
                'name'     => 'PHP Preg Replace Code Execution',
                'pattern'  => '/preg_replace\s*\(\s*[\'"].*\/e[\'"]/i',
                'severity' => 'critical',
                'type'     => 'backdoor',
            ],

            // === OBFUSCATION PATTERNS ===
            [
                'id'       => 'OBFUSC_001',
                'name'     => 'Long Base64 String (likely encoded payload)',
                'pattern'  => '/[\'"][A-Za-z0-9+\/]{200,}={0,2}[\'"]/s',
                'severity' => 'high',
                'type'     => 'obfuscation',
            ],
            [
                'id'       => 'OBFUSC_002',
                'name'     => 'Hex-encoded String Execution',
                'pattern'  => '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){30,}/s', // Increased threshold: 30+ hex sequences (was 10+)
                'severity' => 'high',
                'type'     => 'obfuscation',
                'note'     => 'Legitimate binary data (UTF-8 BOMs, encryption keys) typically <30 sequences',
            ],
            [
                'id'       => 'OBFUSC_003',
                'name'     => 'PHP Variable Function Call',
                'pattern'  => '/\$[a-zA-Z_]+\s*=\s*[\'"][a-zA-Z_]+[\'"]\s*;\s*\$[a-zA-Z_]+\s*\(/i',
                'severity' => 'medium',
                'type'     => 'obfuscation',
            ],
            [
                'id'       => 'OBFUSC_004',
                'name'     => 'chr() String Building',
                'pattern'  => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/i',
                'severity' => 'high',
                'type'     => 'obfuscation',
            ],
            [
                'id'       => 'OBFUSC_005',
                'name'     => 'String Reversal Obfuscation',
                'pattern'  => '/strrev\s*\(\s*[\'"](?:lave|metsys|cexe|edoced_46esab)[\'"]\s*\)/i',
                'severity' => 'critical',
                'type'     => 'obfuscation',
            ],

            // === FAKE PLUGIN PATTERNS (from real breach) ===
            [
                'id'       => 'FAKE_001',
                'name'     => 'Suspicious Plugin Header (generic name)',
                'pattern'  => '/Plugin Name:\s*(WP (Core|Updates?|Security|Cache|Manager) (Pro|Plus|Helper|Tool|Fix))/i',
                'severity' => 'high',
                'type'     => 'fake_plugin',
            ],
            [
                'id'       => 'FAKE_002',
                'name'     => 'Plugin with Remote Code Fetch',
                'pattern'  => '/wp_remote_(get|post)\s*\(.*\beval\b/is',
                'severity' => 'critical',
                'type'     => 'fake_plugin',
            ],
            [
                'id'       => 'FAKE_003',
                'name'     => 'Plugin Fetching and Executing Remote PHP',
                'pattern'  => '/(file_get_contents|curl_exec|wp_remote_get)\s*\(.*?(eval|include|require)\s*\(/is',
                'severity' => 'critical',
                'type'     => 'fake_plugin',
                'exclude_patterns' => [
                    '/wp_remote_get.*wordpress\.org/i', // Legitimate WordPress.org API calls
                    '/include.*ABSPATH/i',              // Legitimate WordPress core includes
                    '/require.*ABSPATH/i',              // Legitimate WordPress core requires
                ],
            ],

            // === MU-PLUGIN BACKDOORS (critical - from real breach) ===
            [
                'id'       => 'MU_001',
                'name'     => 'MU-Plugin Admin Creator',
                'pattern'  => '/wp_insert_user\s*\(\s*array\s*\(.*role.*administrator/is',
                'severity' => 'critical',
                'type'     => 'mu_backdoor',
            ],
            [
                'id'       => 'MU_002',
                'name'     => 'MU-Plugin Authentication Bypass',
                'pattern'  => '/wp_set_current_user\s*\(\s*1\s*\)|wp_set_auth_cookie\s*\(\s*1/i',
                'severity' => 'critical',
                'type'     => 'mu_backdoor',
            ],
            [
                'id'       => 'MU_003',
                'name'     => 'MU-Plugin File Upload Handler',
                'pattern'  => '/\$_FILES\s*\[.*move_uploaded_file/is',
                'severity' => 'critical',
                'type'     => 'mu_backdoor',
                'context'  => 'Only flag in mu-plugins directory, not wp-admin/wp-includes',
            ],

            // === POLYMORPHIC JS (variable names change per load) ===
            [
                'id'       => 'POLY_001',
                'name'     => 'Polymorphic JavaScript Loader',
                'pattern'  => '/document\.write\s*\(\s*unescape\s*\(/i',
                'severity' => 'high',
                'type'     => 'polymorphic',
            ],
            [
                'id'       => 'POLY_002',
                'name'     => 'Dynamic Script Injection',
                'pattern'  => '/createElement\s*\(\s*[\'"]script[\'"]\s*\).*src\s*=.*\+/is',
                'severity' => 'high',
                'type'     => 'polymorphic',
                'exclude_paths' => [
                    'wp-includes/js/jquery',            // jQuery library
                    'wp-includes/js/tinymce',           // TinyMCE editor
                    'wp-includes/js/mediaelement',      // MediaElement player
                    'wp-includes/js/codemirror',        // CodeMirror editor
                    'wp-includes/js/dist',              // WordPress Gutenberg blocks
                ],
            ],

            // === FILE OPERATIONS (suspicious in plugins) ===
            [
                'id'       => 'FILEOP_001',
                'name'     => 'PHP File Write in Plugin',
                'pattern'  => '/file_put_contents\s*\(.*\.(php|phtml|php[345])/i',
                'severity' => 'high',
                'type'     => 'file_operation',
            ],
            [
                'id'       => 'FILEOP_002',
                'name'     => 'Self-Modifying Code',
                'pattern'  => '/file_put_contents\s*\(\s*__FILE__/i',
                'severity' => 'critical',
                'type'     => 'file_operation',
            ],

            // === DATABASE MANIPULATION ===
            [
                'id'       => 'DB_001',
                'name'     => 'Direct SQL User Insertion',
                'pattern'  => '/\$wpdb->(?:query|insert)\s*\(.*wp_users/is',
                'severity' => 'critical',
                'type'     => 'db_manipulation',
            ],
            [
                'id'       => 'DB_002',
                'name'     => 'SQL Option Manipulation',
                'pattern'  => '/\$wpdb->(?:query|update)\s*\(.*wp_options.*(?:siteurl|home|admin_email)/is',
                'severity' => 'critical',
                'type'     => 'db_manipulation',
            ],

            // === NETWORK/COMMUNICATION ===
            [
                'id'       => 'NET_001',
                'name'     => 'Suspicious External Communication',
                'pattern'  => '/(?:file_get_contents|curl_init|fsockopen|wp_remote_)\s*\(\s*[\'"]https?:\/\/(?!(?:api\.wordpress\.org|downloads\.wordpress\.org|wordpress\.org))/i',
                'severity' => 'medium',
                'type'     => 'network',
            ],
            [
                'id'       => 'NET_002',
                'name'     => 'Data Exfiltration Pattern',
                'pattern'  => '/(wp_remote_post|curl_exec|file_get_contents)\s*\(.*\$_(SERVER|COOKIE|SESSION)/is',
                'severity' => 'high',
                'type'     => 'exfiltration',
                'exclude_patterns' => [
                    '/wp_remote_post.*sslverify/i',     // Legitimate WordPress HTTP with SSL verify
                    '/file_get_contents.*ABSPATH/i',    // Reading local WordPress files
                    '/\$_SERVER\[.HTTP_HOST.\]/i',      // Legitimate hostname usage
                ],
            ],

            // === WP FILE MANAGER EXPLOIT (specific to CVE from breach) ===
            [
                'id'       => 'WPFM_001',
                'name'     => 'WP File Manager Exploit Remnant',
                'pattern'  => '/elFinder|elfinder/i',
                'severity' => 'high',
                'type'     => 'exploit',
                'context'  => 'Only flag outside wp-file-manager plugin directory',
            ],

            // === CRYPTO MINING ===
            [
                'id'       => 'CRYPTO_001',
                'name'     => 'Cryptocurrency Miner',
                'pattern'  => '/(?:coinhive|cryptonight|minero|coin-?hive|jsecoin|cryptoloot)/i',
                'severity' => 'high',
                'type'     => 'cryptominer',
            ],

            // === SEO SPAM ===
            [
                'id'       => 'SPAM_001',
                'name'     => 'SEO Spam Injection',
                'pattern'  => '/(?:viagra|cialis|casino|poker|pharmacy|cheap\s*(?:pills|meds))\s*<\/a>/i',
                'severity' => 'medium',
                'type'     => 'seo_spam',
            ],

            // === WEBSHELLS ===
            [
                'id'       => 'WSHELL_001',
                'name'     => 'Known Webshell (c99, r57, WSO)',
                'pattern'  => '/(?:c99shell|r57shell|wso\s*shell|FilesMan|b374k|mini\s*shell)/i',
                'severity' => 'critical',
                'type'     => 'webshell',
            ],
            [
                'id'       => 'WSHELL_002',
                'name'     => 'PHP Info Disclosure in Plugin',
                'pattern'  => '/\bphpinfo\s*\(\s*\)/i',
                'severity' => 'medium',
                'type'     => 'info_disclosure',
            ],
        ];
    }

    public function run_full_scan($type = 'standard') {
        update_option('linzi_scan_status', 'running');
        update_option('linzi_scan_start', time());

        $results = [
            'threats'        => [],
            'files_scanned'  => 0,
            'started_at'     => gmdate('Y-m-d H:i:s'),
            'type'           => $type,
        ];

        // 1. Scan wp-content/plugins
        $results = $this->scan_directory(WP_CONTENT_DIR . '/plugins', $results, $type);

        // 2. Scan wp-content/mu-plugins (CRITICAL - primary persistence mechanism)
        $results = $this->scan_directory(WPMU_PLUGIN_DIR, $results, $type);

        // 3. Scan wp-content/themes
        $results = $this->scan_directory(WP_CONTENT_DIR . '/themes', $results, $type);

        // 4. Scan wp-content/uploads (should NOT contain PHP)
        $results = $this->scan_uploads($results);

        // 5. Scan WordPress root for rogue PHP files
        $results = $this->scan_root_files($results);

        if ($type === 'deep') {
            // 6. Scan wp-includes for modifications
            $results = $this->scan_directory(ABSPATH . 'wp-includes', $results, $type);

            // 7. Scan wp-admin for modifications
            $results = $this->scan_directory(ABSPATH . 'wp-admin', $results, $type);
        }

        // 8. Check for rogue admin accounts
        $rogue_admins = $this->check_rogue_admins();
        if (!empty($rogue_admins)) {
            foreach ($rogue_admins as $admin) {
                $results['threats'][] = [
                    'file_path'   => 'database:wp_users',
                    'threat_type' => 'rogue_admin',
                    'severity'    => 'critical',
                    'signature'   => 'ADMIN_' . $admin['ID'],
                    'description' => sprintf(
                        'Suspicious admin account: %s (email: %s, registered: %s)',
                        $admin['user_login'],
                        $admin['user_email'],
                        $admin['user_registered']
                    ),
                ];
            }
        }

        // 9. Check for vulnerable plugins
        $vulnerable = $this->check_vulnerable_plugins();
        foreach ($vulnerable as $vuln) {
            $results['threats'][] = $vuln;
        }

        // Store threats in database
        $this->store_threats($results['threats']);

        $results['completed_at'] = gmdate('Y-m-d H:i:s');
        $results['threat_count'] = count($results['threats']);

        update_option('linzi_last_scan_time', $results['completed_at']);
        update_option('linzi_last_scan_results', $results);
        update_option('linzi_scan_status', 'complete');

        // Send alert email if threats found
        if (!empty($results['threats'])) {
            $this->send_threat_alert($results);
        }

        // Log the scan
        if (class_exists('Linzi_Activity_Log')) {
            $log = new Linzi_Activity_Log();
            $log->log('scan_complete', 'info', sprintf(
                'Full scan completed: %d files scanned, %d threats found',
                $results['files_scanned'],
                $results['threat_count']
            ));
        }

        return $results;
    }

    private function scan_directory($dir, $results, $type = 'standard') {
        if (!is_dir($dir)) {
            return $results;
        }

        $extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phps', 'shtml'];
        if ($type === 'deep') {
            $extensions = array_merge($extensions, ['js', 'html', 'htm', 'svg']);
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            $ext = strtolower($file->getExtension());
            if (!in_array($ext, $extensions)) continue;

            // Skip our own plugin and quarantine
            $filepath = $file->getPathname();
            if (strpos($filepath, 'linzicontinue') !== false) continue;
            if (strpos($filepath, 'linzi-quarantine') !== false) continue;

            $results['files_scanned']++;

            // Size check - files > 5MB are suspicious for plugins
            if ($file->getSize() > 5 * 1024 * 1024) {
                $results['threats'][] = [
                    'file_path'   => $filepath,
                    'threat_type' => 'suspicious_size',
                    'severity'    => 'medium',
                    'signature'   => 'SIZE_001',
                    'description' => sprintf('Unusually large file (%s)', size_format($file->getSize())),
                ];
            }

            // Read file content and check against signatures
            $content = file_get_contents($filepath);
            if ($content === false) continue;

            // CRITICAL FIX: Skip WordPress core files entirely (wp-admin, wp-includes)
            // Core files contain legitimate patterns that trigger false positives
            // (file_get_contents, wp_remote_post, createElement, etc.)
            if ($this->is_core_file($filepath)) {
                continue; // Skip all signature checks for core files
            }

            foreach ($this->signatures as $sig) {
                if (preg_match($sig['pattern'], $content, $matches)) {
                    // Context check for elFinder (only flag outside its own plugin)
                    if ($sig['id'] === 'WPFM_001' && strpos($filepath, 'wp-file-manager') !== false) {
                        continue;
                    }

                    // REFINEMENT: Check exclude_patterns (content-based exclusions)
                    if (!empty($sig['exclude_patterns'])) {
                        $excluded = false;
                        foreach ($sig['exclude_patterns'] as $exclude_pattern) {
                            if (preg_match($exclude_pattern, $content)) {
                                $excluded = true;
                                break;
                            }
                        }
                        if ($excluded) continue;
                    }

                    // REFINEMENT: Check exclude_paths (location-based exclusions)
                    if (!empty($sig['exclude_paths'])) {
                        $excluded = false;
                        foreach ($sig['exclude_paths'] as $exclude_path) {
                            if (strpos($filepath, $exclude_path) !== false) {
                                $excluded = true;
                                break;
                            }
                        }
                        if ($excluded) continue;
                    }

                    // REFINEMENT: MU_003 context check (only flag in mu-plugins directory)
                    if ($sig['id'] === 'MU_003') {
                        $normalized_path = wp_normalize_path($filepath);
                        $mu_plugins_path = wp_normalize_path(WPMU_PLUGIN_DIR);
                        // Only flag if file is actually IN mu-plugins directory
                        if (strpos($normalized_path, $mu_plugins_path) !== 0) {
                            continue;
                        }
                    }

                    $results['threats'][] = [
                        'file_path'   => $filepath,
                        'threat_type' => $sig['type'],
                        'severity'    => $sig['severity'],
                        'signature'   => $sig['id'],
                        'description' => $sig['name'] . ' - Match: ' . substr($matches[0], 0, 100),
                        'file_hash'   => hash('sha256', $content),
                    ];
                }
            }

            // Check file permissions (world-writable = bad)
            $perms = fileperms($filepath);
            if ($perms !== false && ($perms & 0x0002)) {
                $results['threats'][] = [
                    'file_path'   => $filepath,
                    'threat_type' => 'permissions',
                    'severity'    => 'medium',
                    'signature'   => 'PERM_001',
                    'description' => 'World-writable file detected',
                ];
            }
        }

        return $results;
    }

    private function scan_uploads($results) {
        $uploads_dir = wp_upload_dir()['basedir'];
        if (!is_dir($uploads_dir)) return $results;

        $php_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phps'];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            $ext = strtolower($file->getExtension());
            $results['files_scanned']++;

            // ANY PHP file in uploads is suspicious
            if (in_array($ext, $php_extensions)) {
                $results['threats'][] = [
                    'file_path'   => $file->getPathname(),
                    'threat_type' => 'php_in_uploads',
                    'severity'    => 'critical',
                    'signature'   => 'UPLOAD_001',
                    'description' => 'PHP file found in uploads directory - this should never exist here',
                    'file_hash'   => hash_file('sha256', $file->getPathname()),
                ];
            }

            // Check for double extensions (e.g., image.php.jpg)
            $filename = $file->getFilename();
            if (preg_match('/\.php\d?\./i', $filename) || preg_match('/\.phtml?\./i', $filename)) {
                $results['threats'][] = [
                    'file_path'   => $file->getPathname(),
                    'threat_type' => 'double_extension',
                    'severity'    => 'high',
                    'signature'   => 'UPLOAD_002',
                    'description' => 'Suspicious double extension detected: ' . $filename,
                ];
            }
        }

        return $results;
    }

    private function scan_root_files($results) {
        $known_root_files = [
            'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
            'wp-config.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
            'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
            'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php', '.htaccess',
            'wp-config-sample.php', 'license.txt', 'readme.html',
        ];

        $root_files = glob(ABSPATH . '*.php');
        if (!$root_files) return $results;

        foreach ($root_files as $file) {
            $filename = basename($file);
            $results['files_scanned']++;

            if (!in_array($filename, $known_root_files)) {
                $content = file_get_contents($file);
                $results['threats'][] = [
                    'file_path'   => $file,
                    'threat_type' => 'unknown_root_file',
                    'severity'    => 'high',
                    'signature'   => 'ROOT_001',
                    'description' => 'Unknown PHP file in WordPress root directory: ' . $filename,
                    'file_hash'   => hash('sha256', $content),
                ];

                // Also scan this file for malware signatures
                foreach ($this->signatures as $sig) {
                    if (preg_match($sig['pattern'], $content)) {
                        $results['threats'][] = [
                            'file_path'   => $file,
                            'threat_type' => $sig['type'],
                            'severity'    => 'critical',
                            'signature'   => $sig['id'],
                            'description' => $sig['name'] . ' found in root file: ' . $filename,
                            'file_hash'   => hash('sha256', $content),
                        ];
                    }
                }
            }
        }

        return $results;
    }

    public function check_rogue_admins() {
        global $wpdb;

        $admins = get_users(['role' => 'administrator']);
        $suspicious = [];
        $known_admin_email_domains = $this->get_known_email_domains();

        foreach ($admins as $admin) {
            $is_suspicious = false;
            $reasons = [];

            // Check for recently created accounts
            $registered = strtotime($admin->user_registered);
            if ($registered > (time() - 7 * DAY_IN_SECONDS)) {
                $reasons[] = 'Created within last 7 days';
                $is_suspicious = true;
            }

            // Check for suspicious email patterns
            $email_domain = substr($admin->user_email, strpos($admin->user_email, '@') + 1);
            $suspicious_domains = [
                'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
                'yopmail.com', 'sharklasers.com', 'grr.la', 'guerrillamailblock.com',
                'pokemail.net', 'spam4.me', 'trashmail.com', 'dispostable.com',
            ];
            if (in_array($email_domain, $suspicious_domains)) {
                $reasons[] = 'Disposable email domain: ' . $email_domain;
                $is_suspicious = true;
            }

            // Check for admin accounts with no posts and no recent login
            $post_count = count_user_posts($admin->ID);
            $last_login = get_user_meta($admin->ID, 'last_login', true);
            if ($post_count === 0 && empty($last_login) && $admin->ID !== 1) {
                $reasons[] = 'Zero posts and no login history';
                $is_suspicious = true;
            }

            // Check for username patterns common in hacked accounts
            $suspicious_names = [
                '/^wp_/i', '/^admin\d+$/i', '/^user\d+$/i', '/^support\d*$/i',
                '/^[a-z]{20,}$/i', '/^[a-z0-9]{32}$/i',
            ];
            foreach ($suspicious_names as $pattern) {
                if (preg_match($pattern, $admin->user_login)) {
                    $reasons[] = 'Suspicious username pattern: ' . $admin->user_login;
                    $is_suspicious = true;
                    break;
                }
            }

            if ($is_suspicious) {
                $suspicious[] = [
                    'ID'              => $admin->ID,
                    'user_login'      => $admin->user_login,
                    'user_email'      => $admin->user_email,
                    'user_registered' => $admin->user_registered,
                    'reasons'         => $reasons,
                ];
            }
        }

        return $suspicious;
    }

    private function get_known_email_domains() {
        $admin_email = get_option('admin_email');
        $domain = substr($admin_email, strpos($admin_email, '@') + 1);
        return [$domain];
    }

    public function check_vulnerable_plugins() {
        $threats = [];

        // High-risk plugins (known to be exploited frequently)
        $high_risk_plugins = [
            'wp-file-manager/file_manager.php' => [
                'name'   => 'WP File Manager',
                'reason' => 'Frequently exploited for remote code execution (CVE-2020-25213). REMOVE IMMEDIATELY.',
                'severity' => 'critical',
            ],
            'revslider/revslider.php' => [
                'name'   => 'Revolution Slider (old versions)',
                'reason' => 'Versions < 4.2 have arbitrary file download vulnerability',
                'severity' => 'high',
            ],
            'timthumb.php' => [
                'name'   => 'TimThumb',
                'reason' => 'Known remote code execution vulnerabilities',
                'severity' => 'critical',
            ],
        ];

        $active_plugins = get_option('active_plugins', []);

        foreach ($high_risk_plugins as $plugin_file => $info) {
            if (in_array($plugin_file, $active_plugins) || file_exists(WP_PLUGIN_DIR . '/' . $plugin_file)) {
                $threats[] = [
                    'file_path'   => WP_PLUGIN_DIR . '/' . $plugin_file,
                    'threat_type' => 'vulnerable_plugin',
                    'severity'    => $info['severity'],
                    'signature'   => 'VULN_PLUGIN',
                    'description' => $info['name'] . ': ' . $info['reason'],
                ];
            }
        }

        // Check for plugins with no updates available (abandoned)
        $update_plugins = get_site_transient('update_plugins');
        if ($update_plugins && !empty($update_plugins->no_update)) {
            foreach ($active_plugins as $plugin_file) {
                $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file, false, false);
                if (!empty($plugin_data['Version'])) {
                    // Check if plugin hasn't been updated in wp.org
                    if (isset($update_plugins->response[$plugin_file])) {
                        // Has a pending update - flag as needing update
                        $threats[] = [
                            'file_path'   => WP_PLUGIN_DIR . '/' . $plugin_file,
                            'threat_type' => 'outdated_plugin',
                            'severity'    => 'medium',
                            'signature'   => 'UPDATE_001',
                            'description' => sprintf(
                                '%s has an update available (current: %s, available: %s)',
                                $plugin_data['Name'],
                                $plugin_data['Version'],
                                $update_plugins->response[$plugin_file]->new_version
                            ),
                        ];
                    }
                }
            }
        }

        return $threats;
    }

    private function is_core_file($filepath) {
        $abspath = wp_normalize_path(ABSPATH);
        $filepath = wp_normalize_path($filepath);

        // Check if file is in wp-admin or wp-includes
        return (strpos($filepath, $abspath . 'wp-admin/') === 0 ||
                strpos($filepath, $abspath . 'wp-includes/') === 0);
    }

    public function quarantine_file($filepath) {
        $quarantine_dir = WP_CONTENT_DIR . '/linzi-quarantine';

        if (!file_exists($filepath)) {
            return ['success' => false, 'error' => 'File not found'];
        }

        // Safety: never quarantine core WordPress files
        if ($this->is_core_file($filepath)) {
            return ['success' => false, 'error' => 'Cannot quarantine WordPress core files'];
        }

        // Safety: never quarantine ourselves
        if (strpos($filepath, 'linzicontinue') !== false) {
            return ['success' => false, 'error' => 'Cannot quarantine Linzi files'];
        }

        $filename = basename($filepath) . '.' . time() . '.quarantined';
        $quarantine_path = $quarantine_dir . '/' . $filename;

        // Store metadata about the quarantined file
        $metadata = [
            'original_path' => $filepath,
            'original_hash' => hash_file('sha256', $filepath),
            'original_size' => filesize($filepath),
            'quarantined_at' => gmdate('Y-m-d H:i:s'),
            'original_permissions' => decoct(fileperms($filepath) & 0777),
        ];

        // Move file to quarantine
        if (rename($filepath, $quarantine_path)) {
            // Save metadata
            file_put_contents(
                $quarantine_path . '.meta.json',
                wp_json_encode($metadata, JSON_PRETTY_PRINT)
            );

            // Update threat status in database
            global $wpdb;
            $wpdb->update(
                $wpdb->prefix . 'linzi_threats',
                ['status' => 'quarantined', 'resolved_at' => current_time('mysql')],
                ['file_path' => $filepath, 'status' => 'detected']
            );

            // Log the action
            if (class_exists('Linzi_Activity_Log')) {
                $log = new Linzi_Activity_Log();
                $log->log('file_quarantined', 'warning', 'File quarantined: ' . $filepath, $metadata);
            }

            return ['success' => true, 'message' => 'File quarantined successfully'];
        }

        return ['success' => false, 'error' => 'Failed to move file to quarantine'];
    }

    public function restore_file($quarantine_file) {
        $quarantine_dir = WP_CONTENT_DIR . '/linzi-quarantine';
        $quarantine_path = $quarantine_dir . '/' . $quarantine_file;
        $meta_path = $quarantine_path . '.meta.json';

        if (!file_exists($quarantine_path) || !file_exists($meta_path)) {
            return ['success' => false, 'error' => 'Quarantined file or metadata not found'];
        }

        $metadata = json_decode(file_get_contents($meta_path), true);
        if (!$metadata || empty($metadata['original_path'])) {
            return ['success' => false, 'error' => 'Invalid metadata'];
        }

        if (rename($quarantine_path, $metadata['original_path'])) {
            unlink($meta_path);
            return ['success' => true, 'message' => 'File restored to: ' . $metadata['original_path']];
        }

        return ['success' => false, 'error' => 'Failed to restore file'];
    }

    private function store_threats($threats) {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_threats';

        // Clear old detected (not quarantined) threats before inserting new
        $wpdb->delete($table, ['status' => 'detected']);

        foreach ($threats as $threat) {
            $wpdb->insert($table, [
                'file_path'   => $threat['file_path'],
                'threat_type' => $threat['threat_type'],
                'severity'    => $threat['severity'],
                'signature'   => $threat['signature'] ?? '',
                'description' => $threat['description'] ?? '',
                'file_hash'   => $threat['file_hash'] ?? '',
                'status'      => 'detected',
                'detected_at' => current_time('mysql'),
            ]);
        }
    }

    private function send_threat_alert($results) {
        $options = LinziContinue::get_options();
        $email = $options['email_alerts'];
        if (empty($email)) return;

        $critical_count = 0;
        $high_count = 0;
        foreach ($results['threats'] as $t) {
            if ($t['severity'] === 'critical') $critical_count++;
            if ($t['severity'] === 'high') $high_count++;
        }

        $subject = sprintf(
            '[Linzi] %s: %d threats detected on %s',
            $critical_count > 0 ? 'CRITICAL' : 'Warning',
            count($results['threats']),
            get_bloginfo('name')
        );

        $body = sprintf(
            "Linzi Security Scan Results\n" .
            "====================================\n\n" .
            "Site: %s\n" .
            "Scan completed: %s\n" .
            "Files scanned: %d\n\n" .
            "Threats found: %d\n" .
            "  Critical: %d\n" .
            "  High: %d\n" .
            "  Medium/Low: %d\n\n",
            get_site_url(),
            $results['completed_at'],
            $results['files_scanned'],
            count($results['threats']),
            $critical_count,
            $high_count,
            count($results['threats']) - $critical_count - $high_count
        );

        foreach ($results['threats'] as $threat) {
            $body .= sprintf(
                "[%s] %s\n  File: %s\n  Details: %s\n\n",
                strtoupper($threat['severity']),
                $threat['threat_type'],
                $threat['file_path'],
                $threat['description']
            );
        }

        $body .= "\nLog in to your WordPress admin panel to review and take action.\n";
        $body .= admin_url('admin.php?page=linzicontinue');

        wp_mail($email, $subject, $body);
    }

    public function get_threats() {
        global $wpdb;
        return $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}linzi_threats ORDER BY severity = 'critical' DESC, detected_at DESC",
            ARRAY_A
        );
    }

    public function get_threat_count() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_threats WHERE status = 'detected'"
        );
    }

    public function get_scan_status() {
        return [
            'status'     => get_option('linzi_scan_status', 'idle'),
            'started_at' => get_option('linzi_scan_start', 0),
            'last_scan'  => get_option('linzi_last_scan_time', 'Never'),
        ];
    }
}
