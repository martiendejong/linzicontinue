<?php
if (!defined('ABSPATH')) exit;

/**
 * One-Click Fixer - Resolves security threats with a single button press.
 *
 * Every detected issue gets a corresponding fix action.
 * The Threat Center displays all issues with their fix buttons.
 */
class Linzi_Fixer {

    /**
     * Collect ALL security issues across all modules into a unified list.
     * Each issue has: id, category, severity, title, description, fix_action, fix_label, details
     */
    public function get_all_issues() {
        $issues = [];

        // 1. Malware scan threats
        $issues = array_merge($issues, $this->get_malware_issues());

        // 2. Rogue admin accounts
        $issues = array_merge($issues, $this->get_rogue_admin_issues());

        // 3. Vulnerable/dangerous plugins
        $issues = array_merge($issues, $this->get_vulnerable_plugin_issues());

        // 4. MU-plugin issues
        $issues = array_merge($issues, $this->get_mu_plugin_issues());

        // 5. Hardening gaps
        $issues = array_merge($issues, $this->get_hardening_issues());

        // 6. File permission issues
        $issues = array_merge($issues, $this->get_permission_issues());

        // 7. PHP files in uploads
        $issues = array_merge($issues, $this->get_uploads_php_issues());

        // 8. Outdated plugins
        $issues = array_merge($issues, $this->get_outdated_plugin_issues());

        // 9. WordPress core issues
        $issues = array_merge($issues, $this->get_core_issues());

        // Sort: critical first, then high, medium, low
        $severity_order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
        usort($issues, function ($a, $b) use ($severity_order) {
            return ($severity_order[$a['severity']] ?? 4) - ($severity_order[$b['severity']] ?? 4);
        });

        return $issues;
    }

    /**
     * Execute a fix action by ID.
     */
    public function execute_fix($issue_id, $params = []) {
        // Parse the action type from the issue ID
        $parts = explode(':', $issue_id, 2);
        $action = $parts[0];
        $target = $parts[1] ?? '';

        $log = class_exists('Linzi_Activity_Log') ? new Linzi_Activity_Log() : null;

        switch ($action) {
            case 'quarantine_file':
                return $this->fix_quarantine_file($target, $log);

            case 'delete_file':
                return $this->fix_delete_file($target, $log);

            case 'delete_rogue_admin':
                return $this->fix_delete_rogue_admin((int) $target, $log);

            case 'deactivate_plugin':
                return $this->fix_deactivate_plugin($target, $log);

            case 'delete_plugin':
                return $this->fix_delete_plugin($target, $log);

            case 'delete_mu_plugin':
                return $this->fix_delete_mu_plugin($target, $log);

            case 'quarantine_mu_plugin':
                return $this->fix_quarantine_mu_plugin($target, $log);

            case 'fix_permissions':
                return $this->fix_file_permissions($target, $log);

            case 'apply_hardening':
                return $this->fix_apply_hardening($target, $log);

            case 'block_ip':
                return $this->fix_block_ip($target, $log);

            case 'reset_password':
                return $this->fix_reset_password((int) $target, $log);

            case 'update_plugin':
                return $this->fix_update_plugin($target, $log);

            default:
                return ['success' => false, 'message' => 'Unknown fix action: ' . $action];
        }
    }

    /**
     * Fix ALL critical and high issues at once.
     */
    public function fix_all_critical() {
        $issues = $this->get_all_issues();
        $results = [];
        $fixed = 0;
        $failed = 0;

        foreach ($issues as $issue) {
            if (!in_array($issue['severity'], ['critical', 'high'])) continue;
            if (empty($issue['fix_action'])) continue;

            // Skip destructive actions that need explicit confirmation
            if (in_array($issue['fix_action_type'] ?? '', ['delete_rogue_admin', 'delete_plugin'])) continue;

            $result = $this->execute_fix($issue['fix_action']);
            $results[] = [
                'issue'  => $issue['title'],
                'result' => $result,
            ];

            if ($result['success']) {
                $fixed++;
            } else {
                $failed++;
            }
        }

        return [
            'success' => true,
            'fixed'   => $fixed,
            'failed'  => $failed,
            'total'   => count($results),
            'details' => $results,
        ];
    }

    // ========================================================================
    // Issue collectors
    // ========================================================================

    private function get_malware_issues() {
        global $wpdb;
        $issues = [];

        $threats = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}linzi_threats WHERE status = 'detected' ORDER BY severity = 'critical' DESC",
            ARRAY_A
        );

        foreach ($threats as $t) {
            $is_file = ($t['file_path'] !== 'database:wp_users' && strpos($t['file_path'], 'database:') !== 0);

            $issues[] = [
                'id'              => 'threat_' . $t['id'],
                'category'        => 'malware',
                'category_label'  => 'Malware',
                'category_icon'   => 'dashicons-warning',
                'severity'        => $t['severity'],
                'title'           => $t['threat_type'] . ': ' . basename($t['file_path']),
                'description'     => $t['description'],
                'file_path'       => $t['file_path'],
                'detected_at'     => $t['detected_at'],
                'fix_action'      => $is_file ? 'quarantine_file:' . $t['file_path'] : '',
                'fix_action_type' => $is_file ? 'quarantine_file' : '',
                'fix_label'       => $is_file ? 'Quarantine' : '',
                'fix_icon'        => 'dashicons-lock',
                'fix_confirm'     => 'Move this file to quarantine? It can be restored later.',
                'extra_actions'   => $is_file ? [
                    [
                        'action'  => 'delete_file:' . $t['file_path'],
                        'label'   => 'Delete Permanently',
                        'icon'    => 'dashicons-trash',
                        'confirm' => 'PERMANENTLY delete this file? This cannot be undone!',
                        'danger'  => true,
                    ],
                ] : [],
            ];
        }

        return $issues;
    }

    private function get_rogue_admin_issues() {
        $linzi = LinziContinue::instance();
        $rogue = $linzi->scanner->check_rogue_admins();
        $issues = [];

        foreach ($rogue as $admin) {
            $issues[] = [
                'id'              => 'rogue_admin_' . $admin['ID'],
                'category'        => 'accounts',
                'category_label'  => 'Suspicious Account',
                'category_icon'   => 'dashicons-admin-users',
                'severity'        => 'critical',
                'title'           => 'Suspicious admin: ' . $admin['user_login'],
                'description'     => 'Email: ' . $admin['user_email'] . '. Reasons: ' . implode(', ', $admin['reasons']),
                'file_path'       => '',
                'detected_at'     => $admin['user_registered'],
                'fix_action'      => 'delete_rogue_admin:' . $admin['ID'],
                'fix_action_type' => 'delete_rogue_admin',
                'fix_label'       => 'Delete Account',
                'fix_icon'        => 'dashicons-no',
                'fix_confirm'     => 'DELETE admin account "' . $admin['user_login'] . '" (ID: ' . $admin['ID'] . ')? This will remove the user and reassign their content to you.',
                'extra_actions'   => [
                    [
                        'action'  => 'reset_password:' . $admin['ID'],
                        'label'   => 'Reset Password',
                        'icon'    => 'dashicons-admin-network',
                        'confirm' => 'Reset password for "' . $admin['user_login'] . '"? A new random password will be set.',
                        'danger'  => false,
                    ],
                ],
            ];
        }

        return $issues;
    }

    private function get_vulnerable_plugin_issues() {
        $issues = [];

        // High-risk plugins that should be removed
        $dangerous = [
            'wp-file-manager/file_manager.php' => [
                'name'   => 'WP File Manager',
                'reason' => 'Remote code execution vulnerability (CVE-2020-25213). This plugin was used to hack martiendejong.nl. REMOVE IMMEDIATELY.',
            ],
        ];

        $active_plugins = get_option('active_plugins', []);

        foreach ($dangerous as $plugin_file => $info) {
            $is_active = in_array($plugin_file, $active_plugins);
            $exists = file_exists(WP_PLUGIN_DIR . '/' . $plugin_file);

            if ($exists) {
                $actions = [];
                if ($is_active) {
                    $actions[] = [
                        'action'  => 'delete_plugin:' . $plugin_file,
                        'label'   => 'Delete Plugin',
                        'icon'    => 'dashicons-trash',
                        'confirm' => 'DELETE ' . $info['name'] . '? This will deactivate and remove all plugin files.',
                        'danger'  => true,
                    ];
                }

                $issues[] = [
                    'id'              => 'vuln_plugin_' . sanitize_key($plugin_file),
                    'category'        => 'plugins',
                    'category_label'  => 'Dangerous Plugin',
                    'category_icon'   => 'dashicons-plugins-checked',
                    'severity'        => 'critical',
                    'title'           => $info['name'] . ' - DANGEROUS',
                    'description'     => $info['reason'],
                    'file_path'       => WP_PLUGIN_DIR . '/' . $plugin_file,
                    'detected_at'     => '',
                    'fix_action'      => $is_active ? 'deactivate_plugin:' . $plugin_file : 'delete_plugin:' . $plugin_file,
                    'fix_action_type' => $is_active ? 'deactivate_plugin' : 'delete_plugin',
                    'fix_label'       => $is_active ? 'Deactivate Now' : 'Delete Plugin',
                    'fix_icon'        => $is_active ? 'dashicons-no' : 'dashicons-trash',
                    'fix_confirm'     => ($is_active ? 'Deactivate' : 'Delete') . ' ' . $info['name'] . '?',
                    'extra_actions'   => $actions,
                ];
            }
        }

        return $issues;
    }

    private function get_mu_plugin_issues() {
        global $wpdb;
        $issues = [];
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';

        $unapproved = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}linzi_mu_registry WHERE is_approved = 0",
            ARRAY_A
        );

        foreach ($unapproved as $mu) {
            $filepath = $mu_dir . '/' . $mu['file_name'];
            $content = file_exists($filepath) ? file_get_contents($filepath) : '';

            // Quick risk check
            $risk_indicators = 0;
            if (preg_match('/eval\s*\(/i', $content)) $risk_indicators++;
            if (preg_match('/base64_decode/i', $content)) $risk_indicators++;
            if (preg_match('/wp_insert_user/i', $content)) $risk_indicators++;
            if (preg_match('/shell_exec|system\s*\(|exec\s*\(/i', $content)) $risk_indicators++;

            $severity = $risk_indicators >= 2 ? 'critical' : ($risk_indicators >= 1 ? 'high' : 'medium');

            $issues[] = [
                'id'              => 'mu_' . sanitize_key($mu['file_name']),
                'category'        => 'mu-plugins',
                'category_label'  => 'MU-Plugin',
                'category_icon'   => 'dashicons-admin-plugins',
                'severity'        => $severity,
                'title'           => 'Unapproved mu-plugin: ' . $mu['file_name'],
                'description'     => sprintf(
                    'Size: %s, first seen: %s. %s',
                    size_format($mu['file_size']),
                    $mu['first_seen'],
                    $risk_indicators > 0 ? $risk_indicators . ' suspicious code patterns detected!' : 'No obvious malicious patterns.'
                ),
                'file_path'       => $filepath,
                'detected_at'     => $mu['first_seen'],
                'fix_action'      => $severity === 'critical' ? 'delete_mu_plugin:' . $mu['file_name'] : 'quarantine_mu_plugin:' . $mu['file_name'],
                'fix_action_type' => $severity === 'critical' ? 'delete_mu_plugin' : 'quarantine_mu_plugin',
                'fix_label'       => $severity === 'critical' ? 'Delete' : 'Quarantine',
                'fix_icon'        => $severity === 'critical' ? 'dashicons-trash' : 'dashicons-lock',
                'fix_confirm'     => ($severity === 'critical' ? 'DELETE' : 'Quarantine') . ' mu-plugin "' . $mu['file_name'] . '"?',
                'extra_actions'   => [
                    [
                        'action'  => 'approve_mu:' . $mu['file_name'],
                        'label'   => 'Approve (Safe)',
                        'icon'    => 'dashicons-yes',
                        'confirm' => 'Mark "' . $mu['file_name'] . '" as safe? Only do this if you know this file is legitimate.',
                        'danger'  => false,
                    ],
                ],
            ];
        }

        return $issues;
    }

    private function get_hardening_issues() {
        $issues = [];
        $options = LinziContinue::get_options();

        $checks = [
            [
                'condition'   => empty($options['disable_xmlrpc']),
                'title'       => 'XML-RPC is enabled',
                'description' => 'XML-RPC allows brute force attacks and pingback DDoS. Disable it unless you need it for Jetpack or the WordPress mobile app.',
                'severity'    => 'medium',
                'action'      => 'apply_hardening:disable_xmlrpc',
                'label'       => 'Disable XML-RPC',
            ],
            [
                'condition'   => empty($options['disable_file_editor']) && !defined('DISALLOW_FILE_EDIT'),
                'title'       => 'Theme/Plugin editor is enabled',
                'description' => 'The built-in code editor lets anyone with admin access inject PHP code directly. Disable it.',
                'severity'    => 'high',
                'action'      => 'apply_hardening:disable_file_editor',
                'label'       => 'Disable Editor',
            ],
            [
                'condition'   => empty($options['hide_wp_version']),
                'title'       => 'WordPress version is exposed',
                'description' => 'Your WordPress version is visible in the HTML source. Attackers use this to target known vulnerabilities.',
                'severity'    => 'low',
                'action'      => 'apply_hardening:hide_wp_version',
                'label'       => 'Hide Version',
            ],
            [
                'condition'   => empty($options['firewall_enabled']),
                'title'       => 'Firewall is disabled',
                'description' => 'The web application firewall protects against SQL injection, XSS, and other attacks. Enable it.',
                'severity'    => 'critical',
                'action'      => 'apply_hardening:enable_firewall',
                'label'       => 'Enable Firewall',
            ],
            [
                'condition'   => empty($options['login_protection']),
                'title'       => 'Login protection is disabled',
                'description' => 'Without login protection, attackers can brute force passwords indefinitely.',
                'severity'    => 'high',
                'action'      => 'apply_hardening:enable_login_protection',
                'label'       => 'Enable Protection',
            ],
            [
                'condition'   => empty($options['mu_monitoring']),
                'title'       => 'MU-plugins monitoring is disabled',
                'description' => 'MU-plugins are the #1 persistence mechanism for malware. This MUST be monitored.',
                'severity'    => 'critical',
                'action'      => 'apply_hardening:enable_mu_monitoring',
                'label'       => 'Enable Monitoring',
            ],
            [
                'condition'   => defined('WP_DEBUG') && WP_DEBUG,
                'title'       => 'Debug mode is enabled',
                'description' => 'WP_DEBUG exposes error messages that can reveal sensitive information. Disable in wp-config.php.',
                'severity'    => 'medium',
                'action'      => '',
                'label'       => '',
                'manual'      => 'Set WP_DEBUG to false in wp-config.php',
            ],
            [
                'condition'   => !file_exists(wp_upload_dir()['basedir'] . '/.htaccess'),
                'title'       => 'PHP execution allowed in uploads',
                'description' => 'Attackers can upload PHP files disguised as images and execute them. Block PHP in the uploads directory.',
                'severity'    => 'critical',
                'action'      => 'apply_hardening:protect_uploads',
                'label'       => 'Block PHP in Uploads',
            ],
        ];

        foreach ($checks as $check) {
            if ($check['condition']) {
                $issues[] = [
                    'id'              => 'hardening_' . sanitize_key($check['title']),
                    'category'        => 'hardening',
                    'category_label'  => 'Hardening',
                    'category_icon'   => 'dashicons-lock',
                    'severity'        => $check['severity'],
                    'title'           => $check['title'],
                    'description'     => $check['description'] . (!empty($check['manual']) ? ' (Manual fix: ' . $check['manual'] . ')' : ''),
                    'file_path'       => '',
                    'detected_at'     => '',
                    'fix_action'      => $check['action'],
                    'fix_action_type' => 'apply_hardening',
                    'fix_label'       => $check['label'],
                    'fix_icon'        => 'dashicons-shield',
                    'fix_confirm'     => '',
                    'extra_actions'   => [],
                ];
            }
        }

        return $issues;
    }

    private function get_permission_issues() {
        $issues = [];
        $critical_files = [
            ABSPATH . 'wp-config.php' => '0644',
            ABSPATH . '.htaccess'     => '0644',
        ];

        foreach ($critical_files as $file => $expected) {
            if (!file_exists($file)) continue;

            $perms = fileperms($file);
            if ($perms === false) continue;

            $octal = decoct($perms & 0777);
            $is_world_writable = ($perms & 0x0002);
            $is_world_readable = ($perms & 0x0004);

            if ($is_world_writable) {
                $issues[] = [
                    'id'              => 'perms_' . sanitize_key(basename($file)),
                    'category'        => 'permissions',
                    'category_label'  => 'File Permissions',
                    'category_icon'   => 'dashicons-admin-tools',
                    'severity'        => 'critical',
                    'title'           => basename($file) . ' is world-writable (0' . $octal . ')',
                    'description'     => 'This file can be modified by any process on the server. Should be 0644 or stricter.',
                    'file_path'       => $file,
                    'detected_at'     => '',
                    'fix_action'      => 'fix_permissions:' . $file,
                    'fix_action_type' => 'fix_permissions',
                    'fix_label'       => 'Fix Permissions',
                    'fix_icon'        => 'dashicons-admin-tools',
                    'fix_confirm'     => 'Set ' . basename($file) . ' to 0644?',
                    'extra_actions'   => [],
                ];
            }
        }

        return $issues;
    }

    private function get_uploads_php_issues() {
        $issues = [];
        $uploads_dir = wp_upload_dir()['basedir'];
        if (!is_dir($uploads_dir)) return $issues;

        $php_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phps'];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, $php_extensions)) continue;

            $filepath = $file->getPathname();
            $issues[] = [
                'id'              => 'upload_php_' . md5($filepath),
                'category'        => 'uploads',
                'category_label'  => 'PHP in Uploads',
                'category_icon'   => 'dashicons-media-code',
                'severity'        => 'critical',
                'title'           => 'PHP file in uploads: ' . basename($filepath),
                'description'     => 'PHP files should NEVER exist in the uploads directory. Path: ' . str_replace(ABSPATH, '', $filepath),
                'file_path'       => $filepath,
                'detected_at'     => gmdate('Y-m-d H:i:s', $file->getMTime()),
                'fix_action'      => 'quarantine_file:' . $filepath,
                'fix_action_type' => 'quarantine_file',
                'fix_label'       => 'Quarantine',
                'fix_icon'        => 'dashicons-lock',
                'fix_confirm'     => 'Quarantine ' . basename($filepath) . '?',
                'extra_actions'   => [
                    [
                        'action'  => 'delete_file:' . $filepath,
                        'label'   => 'Delete',
                        'icon'    => 'dashicons-trash',
                        'confirm' => 'Permanently delete ' . basename($filepath) . '?',
                        'danger'  => true,
                    ],
                ],
            ];
        }

        return $issues;
    }

    private function get_outdated_plugin_issues() {
        $issues = [];
        $update_plugins = get_site_transient('update_plugins');

        if ($update_plugins && !empty($update_plugins->response)) {
            foreach ($update_plugins->response as $plugin_file => $info) {
                $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file, false, false);

                $issues[] = [
                    'id'              => 'outdated_' . sanitize_key($plugin_file),
                    'category'        => 'updates',
                    'category_label'  => 'Plugin Update',
                    'category_icon'   => 'dashicons-update',
                    'severity'        => 'medium',
                    'title'           => ($plugin_data['Name'] ?: $plugin_file) . ' needs update',
                    'description'     => sprintf(
                        'Current: %s, Available: %s. Outdated plugins may contain known vulnerabilities.',
                        $plugin_data['Version'] ?: '?',
                        $info->new_version ?? '?'
                    ),
                    'file_path'       => '',
                    'detected_at'     => '',
                    'fix_action'      => 'update_plugin:' . $plugin_file,
                    'fix_action_type' => 'update_plugin',
                    'fix_label'       => 'Update Now',
                    'fix_icon'        => 'dashicons-update',
                    'fix_confirm'     => 'Update ' . ($plugin_data['Name'] ?: $plugin_file) . '?',
                    'extra_actions'   => [],
                ];
            }
        }

        return $issues;
    }

    private function get_core_issues() {
        $issues = [];

        // Check for default "admin" username
        $admin_user = get_user_by('login', 'admin');
        if ($admin_user) {
            $issues[] = [
                'id'              => 'core_admin_username',
                'category'        => 'accounts',
                'category_label'  => 'Account Security',
                'category_icon'   => 'dashicons-admin-users',
                'severity'        => 'medium',
                'title'           => 'Default "admin" username exists',
                'description'     => 'The username "admin" is the first target for brute force attacks. Consider creating a new admin account with a unique name and deleting this one.',
                'file_path'       => '',
                'detected_at'     => '',
                'fix_action'      => '',
                'fix_action_type' => '',
                'fix_label'       => '',
                'fix_icon'        => '',
                'fix_confirm'     => '',
                'extra_actions'   => [],
                'manual'          => 'Create a new admin account, transfer content, then delete the "admin" account.',
            ];
        }

        // Check if user registration is open with admin as default role
        if (get_option('users_can_register') && get_option('default_role') === 'administrator') {
            $issues[] = [
                'id'              => 'core_open_admin_registration',
                'category'        => 'config',
                'category_label'  => 'Configuration',
                'category_icon'   => 'dashicons-admin-settings',
                'severity'        => 'critical',
                'title'           => 'Open registration with admin role!',
                'description'     => 'Anyone can register as an administrator. This is almost certainly a hack or misconfiguration.',
                'file_path'       => '',
                'detected_at'     => '',
                'fix_action'      => 'apply_hardening:fix_registration',
                'fix_action_type' => 'apply_hardening',
                'fix_label'       => 'Fix Now',
                'fix_icon'        => 'dashicons-shield',
                'fix_confirm'     => 'Change default role to "subscriber" and disable open registration?',
                'extra_actions'   => [],
            ];
        }

        return $issues;
    }

    // ========================================================================
    // Fix executors
    // ========================================================================

    private function fix_quarantine_file($filepath, $log) {
        $linzi = LinziContinue::instance();
        $result = $linzi->scanner->quarantine_file($filepath);

        if ($result['success'] && $log) {
            $log->log('fix_applied', 'info', 'File quarantined: ' . $filepath);
        }

        return $result;
    }

    private function fix_delete_file($filepath, $log) {
        if (!file_exists($filepath)) {
            return ['success' => false, 'message' => 'File not found'];
        }

        // Safety checks
        $abspath = wp_normalize_path(ABSPATH);
        $normalized = wp_normalize_path($filepath);

        // Never delete core files
        if (strpos($normalized, $abspath . 'wp-admin/') === 0 ||
            strpos($normalized, $abspath . 'wp-includes/') === 0) {
            return ['success' => false, 'message' => 'Cannot delete WordPress core files'];
        }

        // Never delete ourselves
        if (strpos($filepath, 'linzicontinue') !== false) {
            return ['success' => false, 'message' => 'Cannot delete Linzi files'];
        }

        if (unlink($filepath)) {
            if ($log) {
                $log->log('fix_applied', 'warning', 'File permanently deleted: ' . $filepath);
            }

            // Update threats table
            global $wpdb;
            $wpdb->update(
                $wpdb->prefix . 'linzi_threats',
                ['status' => 'deleted', 'resolved_at' => current_time('mysql')],
                ['file_path' => $filepath, 'status' => 'detected']
            );

            return ['success' => true, 'message' => 'File deleted: ' . basename($filepath)];
        }

        return ['success' => false, 'message' => 'Failed to delete file (permission denied?)'];
    }

    private function fix_delete_rogue_admin($user_id, $log) {
        $user = get_userdata($user_id);
        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }

        // Never delete the current user
        if ($user_id === get_current_user_id()) {
            return ['success' => false, 'message' => 'Cannot delete your own account'];
        }

        // Never delete user ID 1
        if ($user_id === 1) {
            return ['success' => false, 'message' => 'Cannot delete the original admin account (ID 1)'];
        }

        $username = $user->user_login;

        // Reassign content to current user
        require_once ABSPATH . 'wp-admin/includes/user.php';
        wp_delete_user($user_id, get_current_user_id());

        if ($log) {
            $log->log('fix_applied', 'critical', 'Rogue admin account deleted: ' . $username . ' (ID: ' . $user_id . ')');
        }

        return ['success' => true, 'message' => 'Admin account "' . $username . '" deleted. Content reassigned to you.'];
    }

    private function fix_deactivate_plugin($plugin_file, $log) {
        if (!is_plugin_active($plugin_file)) {
            return ['success' => true, 'message' => 'Plugin already inactive'];
        }

        deactivate_plugins($plugin_file);

        if ($log) {
            $log->log('fix_applied', 'warning', 'Dangerous plugin deactivated: ' . $plugin_file);
        }

        return ['success' => true, 'message' => 'Plugin deactivated: ' . $plugin_file];
    }

    private function fix_delete_plugin($plugin_file, $log) {
        // Deactivate first if active
        if (is_plugin_active($plugin_file)) {
            deactivate_plugins($plugin_file);
        }

        $result = delete_plugins([$plugin_file]);

        if (is_wp_error($result)) {
            return ['success' => false, 'message' => $result->get_error_message()];
        }

        if ($log) {
            $log->log('fix_applied', 'critical', 'Dangerous plugin deleted: ' . $plugin_file);
        }

        return ['success' => true, 'message' => 'Plugin deleted: ' . $plugin_file];
    }

    private function fix_delete_mu_plugin($filename, $log) {
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $filepath = $mu_dir . '/' . $filename;

        if (!file_exists($filepath)) {
            return ['success' => false, 'message' => 'MU-plugin file not found'];
        }

        if (unlink($filepath)) {
            // Remove from registry
            global $wpdb;
            $wpdb->delete($wpdb->prefix . 'linzi_mu_registry', ['file_name' => $filename]);

            if ($log) {
                $log->log('fix_applied', 'critical', 'MU-plugin deleted: ' . $filename);
            }

            return ['success' => true, 'message' => 'MU-plugin deleted: ' . $filename];
        }

        return ['success' => false, 'message' => 'Failed to delete mu-plugin (permission denied?)'];
    }

    private function fix_quarantine_mu_plugin($filename, $log) {
        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        $filepath = $mu_dir . '/' . $filename;

        $linzi = LinziContinue::instance();
        $result = $linzi->scanner->quarantine_file($filepath);

        if ($result['success']) {
            // Remove from registry
            global $wpdb;
            $wpdb->delete($wpdb->prefix . 'linzi_mu_registry', ['file_name' => $filename]);

            if ($log) {
                $log->log('fix_applied', 'warning', 'MU-plugin quarantined: ' . $filename);
            }
        }

        return $result;
    }

    private function fix_file_permissions($filepath, $log) {
        if (!file_exists($filepath)) {
            return ['success' => false, 'message' => 'File not found'];
        }

        if (chmod($filepath, 0644)) {
            if ($log) {
                $log->log('fix_applied', 'info', 'File permissions fixed to 0644: ' . $filepath);
            }
            return ['success' => true, 'message' => 'Permissions set to 0644 for ' . basename($filepath)];
        }

        return ['success' => false, 'message' => 'Failed to change permissions (may need server-level access)'];
    }

    private function fix_apply_hardening($action, $log) {
        $options = get_option('linzi_options', []);
        $defaults = LinziContinue::get_options();
        $options = wp_parse_args($options, $defaults);

        switch ($action) {
            case 'disable_xmlrpc':
                $options['disable_xmlrpc'] = true;
                break;
            case 'disable_file_editor':
                $options['disable_file_editor'] = true;
                break;
            case 'hide_wp_version':
                $options['hide_wp_version'] = true;
                break;
            case 'enable_firewall':
                $options['firewall_enabled'] = true;
                break;
            case 'enable_login_protection':
                $options['login_protection'] = true;
                break;
            case 'enable_mu_monitoring':
                $options['mu_monitoring'] = true;
                break;
            case 'protect_uploads':
                $linzi = LinziContinue::instance();
                $linzi->hardening->protect_uploads_directory();
                if ($log) {
                    $log->log('fix_applied', 'info', 'PHP execution blocked in uploads directory');
                }
                return ['success' => true, 'message' => 'PHP execution blocked in uploads directory'];
            case 'fix_registration':
                update_option('users_can_register', 0);
                update_option('default_role', 'subscriber');
                if ($log) {
                    $log->log('fix_applied', 'critical', 'Fixed dangerous registration settings: disabled open registration, set default role to subscriber');
                }
                return ['success' => true, 'message' => 'Registration disabled, default role set to subscriber'];
            default:
                return ['success' => false, 'message' => 'Unknown hardening action'];
        }

        update_option('linzi_options', $options);

        if ($log) {
            $log->log('fix_applied', 'info', 'Hardening applied: ' . $action);
        }

        return ['success' => true, 'message' => 'Hardening applied: ' . str_replace('_', ' ', $action)];
    }

    private function fix_block_ip($ip, $log) {
        $options = get_option('linzi_options', []);
        $defaults = LinziContinue::get_options();
        $options = wp_parse_args($options, $defaults);

        if (!in_array($ip, $options['blocked_ips'])) {
            $options['blocked_ips'][] = $ip;
            update_option('linzi_options', $options);
        }

        if ($log) {
            $log->log('fix_applied', 'warning', 'IP permanently blocked: ' . $ip);
        }

        return ['success' => true, 'message' => 'IP blocked: ' . $ip];
    }

    private function fix_reset_password($user_id, $log) {
        $user = get_userdata($user_id);
        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }

        // Generate random password
        $new_password = wp_generate_password(24, true, true);
        wp_set_password($new_password, $user_id);

        // Destroy all sessions for this user
        $sessions = WP_Session_Tokens::get_instance($user_id);
        $sessions->destroy_all();

        if ($log) {
            $log->log('fix_applied', 'warning', 'Password reset and sessions destroyed for: ' . $user->user_login);
        }

        return [
            'success' => true,
            'message' => 'Password reset for "' . $user->user_login . '". All their sessions have been terminated. They will need to use "Lost Password" to regain access.',
        ];
    }

    private function fix_update_plugin($plugin_file, $log) {
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        $skin = new WP_Ajax_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader($skin);
        $result = $upgrader->upgrade($plugin_file);

        if ($result === true || !is_wp_error($result)) {
            if ($log) {
                $log->log('fix_applied', 'info', 'Plugin updated: ' . $plugin_file);
            }
            return ['success' => true, 'message' => 'Plugin updated successfully'];
        }

        $error = is_wp_error($result) ? $result->get_error_message() : 'Update failed';
        return ['success' => false, 'message' => $error];
    }

    /**
     * Get summary counts by severity.
     */
    public function get_summary() {
        $issues = $this->get_all_issues();
        $summary = [
            'total'    => count($issues),
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'low'      => 0,
            'fixable'  => 0,
        ];

        foreach ($issues as $issue) {
            $summary[$issue['severity']]++;
            if (!empty($issue['fix_action'])) {
                $summary['fixable']++;
            }
        }

        return $summary;
    }
}
