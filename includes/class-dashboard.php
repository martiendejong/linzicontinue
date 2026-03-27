<?php
if (!defined('ABSPATH')) exit;

class Linzi_Dashboard {

    public function __construct() {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);

        // AJAX handlers
        add_action('wp_ajax_linzi_run_scan', [$this, 'ajax_run_scan']);
        add_action('wp_ajax_linzi_quarantine', [$this, 'ajax_quarantine']);
        add_action('wp_ajax_linzi_approve_mu', [$this, 'ajax_approve_mu']);
        add_action('wp_ajax_linzi_get_activity', [$this, 'ajax_get_activity']);
        add_action('wp_ajax_linzi_dismiss_threat', [$this, 'ajax_dismiss_threat']);
        add_action('wp_ajax_linzi_fix_issue', [$this, 'ajax_fix_issue']);
        add_action('wp_ajax_linzi_fix_all', [$this, 'ajax_fix_all']);
        add_action('wp_ajax_linzi_get_issues', [$this, 'ajax_get_issues']);

        // Admin bar indicator
        add_action('admin_bar_menu', [$this, 'admin_bar_indicator'], 999);

        // Admin notice for critical issues
        add_action('admin_notices', [$this, 'critical_notice']);
    }

    public function add_menu() {
        $linzi = LinziContinue::instance();
        $summary = $linzi->fixer->get_summary();
        $badge = $summary['critical'] > 0 ? ' <span class="awaiting-mod">' . $summary['critical'] . '</span>' : '';

        add_menu_page(
            'Linzi Security',
            'Linzi' . $badge,
            'manage_options',
            'linzicontinue',
            [$this, 'render_threat_center'],
            'dashicons-shield',
            3
        );

        add_submenu_page('linzicontinue', 'Threat Center', 'Threat Center', 'manage_options', 'linzicontinue', [$this, 'render_threat_center']);
        add_submenu_page('linzicontinue', 'Firewall', 'Firewall', 'manage_options', 'linzicontinue-firewall', [$this, 'render_firewall']);
        add_submenu_page('linzicontinue', 'Scanner', 'Malware Scanner', 'manage_options', 'linzicontinue-scanner', [$this, 'render_scanner']);
        add_submenu_page('linzicontinue', 'MU-Plugins', 'MU-Plugins Guard', 'manage_options', 'linzicontinue-mu', [$this, 'render_mu_monitor']);
        add_submenu_page('linzicontinue', 'Activity Log', 'Activity Log', 'manage_options', 'linzicontinue-activity', [$this, 'render_activity']);
        add_submenu_page('linzicontinue', 'Hardening', 'Hardening', 'manage_options', 'linzicontinue-hardening', [$this, 'render_hardening']);
        add_submenu_page('linzicontinue', 'Settings', 'Settings', 'manage_options', 'linzicontinue-settings', [$this, 'render_settings']);
    }

    public function enqueue_assets($hook) {
        if (strpos($hook, 'linzicontinue') === false) return;

        wp_enqueue_style('linzi-admin', LINZI_PLUGIN_URL . 'admin/css/admin.css', [], LINZI_VERSION);
        wp_enqueue_script('linzi-admin', LINZI_PLUGIN_URL . 'admin/js/admin.js', ['jquery'], LINZI_VERSION, true);
        wp_localize_script('linzi-admin', 'linziData', [
            'ajaxUrl'  => admin_url('admin-ajax.php'),
            'restUrl'  => rest_url('linzicontinue/v1/'),
            'nonce'    => wp_create_nonce('linzi_nonce'),
            'restNonce' => wp_create_nonce('wp_rest'),
        ]);
    }

    public function admin_bar_indicator($admin_bar) {
        if (!current_user_can('manage_options')) return;

        $linzi = LinziContinue::instance();
        $summary = $linzi->fixer->get_summary();
        $score = $linzi->calculate_security_score();

        $color = $score >= 80 ? '#46b450' : ($score >= 50 ? '#ffb900' : '#dc3232');

        $title = sprintf('<span style="color:%s">&#x1F6E1; Linzi</span>', $color);

        if ($summary['critical'] > 0) {
            $title .= sprintf(
                ' <span style="background:#dc3232;color:#fff;padding:0 6px;border-radius:10px;font-size:11px;">%d</span>',
                $summary['critical']
            );
        } elseif ($summary['total'] > 0) {
            $title .= sprintf(
                ' <span style="background:#ffb900;color:#333;padding:0 6px;border-radius:10px;font-size:11px;">%d</span>',
                $summary['total']
            );
        }

        $admin_bar->add_node([
            'id'    => 'linzicontinue',
            'title' => $title,
            'href'  => admin_url('admin.php?page=linzicontinue'),
        ]);
    }

    public function critical_notice() {
        if (!current_user_can('manage_options')) return;

        $screen = get_current_screen();
        if ($screen && strpos($screen->id, 'linzicontinue') !== false) return;

        $linzi = LinziContinue::instance();
        $summary = $linzi->fixer->get_summary();

        if ($summary['critical'] > 0) {
            printf(
                '<div class="notice notice-error"><p><strong>&#x26A0; Linzi:</strong> %d critical security %s detected. <a href="%s">View & Fix Now</a></p></div>',
                $summary['critical'],
                $summary['critical'] === 1 ? 'issue' : 'issues',
                admin_url('admin.php?page=linzicontinue')
            );
        }
    }

    // ========================================================================
    // AJAX Handlers
    // ========================================================================

    public function ajax_run_scan() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $type = sanitize_text_field($_POST['scan_type'] ?? 'standard');
        $linzi = LinziContinue::instance();
        $results = $linzi->scanner->run_full_scan($type);

        wp_send_json_success($results);
    }

    public function ajax_quarantine() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $file = sanitize_text_field($_POST['file'] ?? '');
        $linzi = LinziContinue::instance();
        $result = $linzi->scanner->quarantine_file($file);

        wp_send_json($result);
    }

    public function ajax_approve_mu() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $filename = sanitize_file_name($_POST['filename'] ?? '');
        $linzi = LinziContinue::instance();
        $linzi->mu_monitor->approve_mu_plugin($filename);

        wp_send_json_success(['message' => 'MU-plugin approved']);
    }

    public function ajax_get_activity() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $page = absint($_POST['page'] ?? 1);
        $linzi = LinziContinue::instance();
        $logs = $linzi->activity_log->get_logs($page);

        wp_send_json_success($logs);
    }

    public function ajax_dismiss_threat() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        global $wpdb;
        $threat_id = absint($_POST['threat_id'] ?? 0);

        $wpdb->update(
            $wpdb->prefix . 'linzi_threats',
            ['status' => 'dismissed', 'resolved_at' => current_time('mysql')],
            ['id' => $threat_id]
        );

        wp_send_json_success(['message' => 'Threat dismissed']);
    }

    public function ajax_fix_issue() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $issue_id = sanitize_text_field($_POST['issue_id'] ?? '');
        if (empty($issue_id)) {
            wp_send_json_error(['message' => 'No issue ID provided']);
        }

        $linzi = LinziContinue::instance();
        $result = $linzi->fixer->execute_fix($issue_id);

        if ($result['success']) {
            wp_send_json_success($result);
        } else {
            wp_send_json_error($result);
        }
    }

    public function ajax_fix_all() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $linzi = LinziContinue::instance();
        $result = $linzi->fixer->fix_all_critical();

        wp_send_json_success($result);
    }

    public function ajax_get_issues() {
        check_ajax_referer('linzi_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_die('Unauthorized');

        $linzi = LinziContinue::instance();
        $issues = $linzi->fixer->get_all_issues();
        $summary = $linzi->fixer->get_summary();

        wp_send_json_success([
            'issues'  => $issues,
            'summary' => $summary,
        ]);
    }

    // ========================================================================
    // THREAT CENTER - The main dashboard
    // ========================================================================

    public function render_threat_center() {
        $linzi = LinziContinue::instance();
        $issues = $linzi->fixer->get_all_issues();
        $summary = $linzi->fixer->get_summary();
        $score = $linzi->calculate_security_score();
        $blocked = $linzi->firewall->get_blocked_count();
        $last_scan = get_option('linzi_last_scan_time', 'Never');

        $score_color = $score >= 80 ? '#46b450' : ($score >= 50 ? '#ffb900' : '#dc3232');
        $score_label = $score >= 80 ? 'Protected' : ($score >= 50 ? 'At Risk' : 'Compromised');

        ?>
        <div class="wrap linzi-wrap">
            <h1 class="linzi-header">
                <span class="dashicons dashicons-shield" style="font-size:30px;margin-right:10px;"></span>
                Linzi Threat Center
                <span class="linzi-version">v<?php echo esc_html(LINZI_VERSION); ?></span>
            </h1>

            <!-- Top Bar: Score + Scan + Fix All -->
            <div class="linzi-topbar">
                <div class="linzi-topbar-score" style="border-color:<?php echo esc_attr($score_color); ?>">
                    <div class="linzi-topbar-score-num" style="color:<?php echo esc_attr($score_color); ?>"><?php echo esc_html($score); ?></div>
                    <div class="linzi-topbar-score-label"><?php echo esc_html($score_label); ?></div>
                </div>

                <div class="linzi-topbar-stats">
                    <div class="linzi-topbar-stat">
                        <span class="linzi-topbar-stat-num linzi-color-critical"><?php echo esc_html($summary['critical']); ?></span>
                        <span>Critical</span>
                    </div>
                    <div class="linzi-topbar-stat">
                        <span class="linzi-topbar-stat-num linzi-color-high"><?php echo esc_html($summary['high']); ?></span>
                        <span>High</span>
                    </div>
                    <div class="linzi-topbar-stat">
                        <span class="linzi-topbar-stat-num linzi-color-medium"><?php echo esc_html($summary['medium']); ?></span>
                        <span>Medium</span>
                    </div>
                    <div class="linzi-topbar-stat">
                        <span class="linzi-topbar-stat-num linzi-color-low"><?php echo esc_html($summary['low']); ?></span>
                        <span>Low</span>
                    </div>
                    <div class="linzi-topbar-stat">
                        <span class="linzi-topbar-stat-num" style="color:#0073aa"><?php echo esc_html(number_format($blocked)); ?></span>
                        <span>Blocked</span>
                    </div>
                </div>

                <div class="linzi-topbar-actions">
                    <button class="button button-primary button-hero linzi-scan-btn" data-type="standard">
                        <span class="dashicons dashicons-search" style="margin-top:4px"></span> Scan Now
                    </button>
                    <?php if ($summary['critical'] + $summary['high'] > 0) : ?>
                    <button class="button button-hero linzi-fix-all-btn" style="background:#dc3232;color:#fff;border-color:#b02a2a;">
                        <span class="dashicons dashicons-yes-alt" style="margin-top:4px"></span> Fix All Critical & High
                    </button>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Scan Progress -->
            <div id="linzi-scan-progress" style="display:none;">
                <div class="linzi-section">
                    <h2>Scanning...</h2>
                    <div class="linzi-progress-bar"><div class="linzi-progress-fill linzi-progress-animated"></div></div>
                    <p class="linzi-scan-status-text">Scanning files for malware, checking accounts, hardening status...</p>
                </div>
            </div>

            <!-- Issues List -->
            <div id="linzi-issues-container">
            <?php if (empty($issues)) : ?>
                <div class="linzi-section">
                    <div class="linzi-all-clear">
                        <div class="linzi-all-clear-icon">&#x2705;</div>
                        <h2>All Clear</h2>
                        <p>No security issues detected. Your site is protected.</p>
                        <p class="description">Last scan: <?php echo esc_html($last_scan); ?></p>
                    </div>
                </div>
            <?php else : ?>

                <?php
                // Group issues by category
                $grouped = [];
                foreach ($issues as $issue) {
                    $grouped[$issue['category']][] = $issue;
                }
                ?>

                <?php foreach ($grouped as $category => $cat_issues) :
                    $first = $cat_issues[0];
                    $cat_critical = count(array_filter($cat_issues, function($i) { return $i['severity'] === 'critical'; }));
                    $cat_high = count(array_filter($cat_issues, function($i) { return $i['severity'] === 'high'; }));
                ?>
                <div class="linzi-issue-group">
                    <div class="linzi-issue-group-header">
                        <span class="dashicons <?php echo esc_attr($first['category_icon']); ?>"></span>
                        <h2><?php echo esc_html($first['category_label']); ?></h2>
                        <span class="linzi-issue-count"><?php echo count($cat_issues); ?> <?php echo count($cat_issues) === 1 ? 'issue' : 'issues'; ?></span>
                        <?php if ($cat_critical > 0) : ?>
                            <span class="linzi-severity linzi-severity-critical"><?php echo $cat_critical; ?> CRITICAL</span>
                        <?php endif; ?>
                        <?php if ($cat_high > 0) : ?>
                            <span class="linzi-severity linzi-severity-high"><?php echo $cat_high; ?> HIGH</span>
                        <?php endif; ?>
                    </div>

                    <?php foreach ($cat_issues as $issue) : ?>
                    <div class="linzi-issue-card linzi-issue-<?php echo esc_attr($issue['severity']); ?>" data-issue-id="<?php echo esc_attr($issue['id']); ?>">
                        <div class="linzi-issue-severity">
                            <span class="linzi-severity linzi-severity-<?php echo esc_attr($issue['severity']); ?>">
                                <?php echo esc_html(strtoupper($issue['severity'])); ?>
                            </span>
                        </div>

                        <div class="linzi-issue-content">
                            <div class="linzi-issue-title"><?php echo esc_html($issue['title']); ?></div>
                            <div class="linzi-issue-desc"><?php echo esc_html($issue['description']); ?></div>
                            <?php if (!empty($issue['file_path'])) : ?>
                                <div class="linzi-issue-path"><code><?php echo esc_html($issue['file_path']); ?></code></div>
                            <?php endif; ?>
                            <?php if (!empty($issue['detected_at'])) : ?>
                                <div class="linzi-issue-time">Detected: <?php echo esc_html($issue['detected_at']); ?></div>
                            <?php endif; ?>
                            <?php if (!empty($issue['manual'])) : ?>
                                <div class="linzi-issue-manual"><strong>Manual fix:</strong> <?php echo esc_html($issue['manual']); ?></div>
                            <?php endif; ?>
                        </div>

                        <div class="linzi-issue-actions">
                            <?php if (!empty($issue['fix_action'])) : ?>
                            <button class="button button-primary linzi-fix-btn"
                                    data-action="<?php echo esc_attr($issue['fix_action']); ?>"
                                    data-confirm="<?php echo esc_attr($issue['fix_confirm']); ?>"
                                    title="<?php echo esc_attr($issue['fix_label']); ?>">
                                <span class="dashicons <?php echo esc_attr($issue['fix_icon']); ?>" style="margin-top:4px"></span>
                                <?php echo esc_html($issue['fix_label']); ?>
                            </button>
                            <?php endif; ?>

                            <?php if (!empty($issue['extra_actions'])) : ?>
                                <?php foreach ($issue['extra_actions'] as $extra) : ?>
                                <button class="button <?php echo !empty($extra['danger']) ? 'linzi-btn-danger' : ''; ?> linzi-fix-btn"
                                        data-action="<?php echo esc_attr($extra['action']); ?>"
                                        data-confirm="<?php echo esc_attr($extra['confirm']); ?>">
                                    <span class="dashicons <?php echo esc_attr($extra['icon']); ?>" style="margin-top:4px"></span>
                                    <?php echo esc_html($extra['label']); ?>
                                </button>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endforeach; ?>

            <?php endif; ?>
            </div>

            <!-- Navigation Cards -->
            <div class="linzi-section" style="margin-top:20px">
                <h2>Tools</h2>
                <div class="linzi-actions-grid">
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-scanner'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-search"></span>
                        <span>Deep Scanner</span>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-mu'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-admin-plugins"></span>
                        <span>MU-Plugins Guard</span>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-firewall'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-shield-alt"></span>
                        <span>Firewall Log</span>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-hardening'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-lock"></span>
                        <span>Hardening</span>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-activity'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-list-view"></span>
                        <span>Activity Log</span>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=linzicontinue-settings'); ?>" class="linzi-action-card">
                        <span class="dashicons dashicons-admin-generic"></span>
                        <span>Settings</span>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }

    // ========================================================================
    // Other page renderers (firewall, scanner, mu, activity, hardening, settings)
    // ========================================================================

    public function render_firewall() {
        $linzi = LinziContinue::instance();
        $top_ips = $linzi->firewall->get_top_blocked_ips();
        $attack_types = $linzi->firewall->get_attack_types();
        $blocked_today = $linzi->firewall->get_blocked_today();

        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-shield-alt"></span> Firewall</h1>

            <div class="linzi-stats-grid" style="grid-template-columns: repeat(2, 1fr);">
                <div class="linzi-stat-card linzi-stat-info">
                    <div class="linzi-stat-number"><?php echo esc_html($blocked_today); ?></div>
                    <div class="linzi-stat-label">Blocked Today</div>
                </div>
                <div class="linzi-stat-card linzi-stat-info">
                    <div class="linzi-stat-number"><?php echo esc_html(number_format($linzi->firewall->get_blocked_count())); ?></div>
                    <div class="linzi-stat-label">Total Blocked</div>
                </div>
            </div>

            <div class="linzi-section">
                <h2>Top Blocked IPs</h2>
                <table class="widefat linzi-table">
                    <thead><tr><th>IP Address</th><th>Block Count</th><th>Last Blocked</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($top_ips as $entry) : ?>
                        <tr>
                            <td><code><?php echo esc_html($entry['ip_address']); ?></code></td>
                            <td><?php echo esc_html($entry['block_count']); ?></td>
                            <td><?php echo esc_html($entry['last_blocked']); ?></td>
                            <td><button class="button linzi-fix-btn" data-action="block_ip:<?php echo esc_attr($entry['ip_address']); ?>" data-confirm="Permanently block <?php echo esc_attr($entry['ip_address']); ?>?">Block Permanently</button></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (empty($top_ips)) : ?>
                        <tr><td colspan="4">No blocked IPs yet.</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="linzi-section">
                <h2>Attack Types (Last 7 Days)</h2>
                <table class="widefat linzi-table">
                    <thead><tr><th>Attack Type</th><th>Count</th></tr></thead>
                    <tbody>
                    <?php foreach ($attack_types as $type) : ?>
                        <tr>
                            <td><?php echo esc_html($type['rule_matched']); ?></td>
                            <td><?php echo esc_html($type['count']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (empty($attack_types)) : ?>
                        <tr><td colspan="2">No attacks detected.</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    public function render_scanner() {
        $linzi = LinziContinue::instance();
        $last_results = get_option('linzi_last_scan_results', []);

        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-search"></span> Malware Scanner</h1>

            <div class="linzi-section">
                <p>
                    <button class="button button-primary button-hero linzi-scan-btn" data-type="standard">Standard Scan</button>
                    <button class="button button-hero linzi-scan-btn" data-type="deep">Deep Scan</button>
                </p>
                <p class="description">Standard: plugins, themes, mu-plugins, uploads, root. Deep: also wp-includes and wp-admin.</p>
            </div>

            <div id="linzi-scan-progress" style="display:none;">
                <div class="linzi-section">
                    <h2>Scanning...</h2>
                    <div class="linzi-progress-bar"><div class="linzi-progress-fill linzi-progress-animated"></div></div>
                    <p class="linzi-scan-status-text">Scanning files...</p>
                </div>
            </div>

            <div id="linzi-scan-results">
                <?php if (!empty($last_results)) : ?>
                <div class="linzi-section">
                    <h2>Last Scan</h2>
                    <p>Files: <strong><?php echo esc_html(number_format($last_results['files_scanned'] ?? 0)); ?></strong> | Threats: <strong><?php echo esc_html($last_results['threat_count'] ?? 0); ?></strong> | Time: <strong><?php echo esc_html($last_results['completed_at'] ?? 'N/A'); ?></strong></p>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    public function render_mu_monitor() {
        $linzi = LinziContinue::instance();
        $mu_plugins = $linzi->mu_monitor->get_mu_plugin_list();

        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-admin-plugins"></span> MU-Plugins Guard</h1>

            <div class="notice notice-info">
                <p><strong>MU-plugins are the #1 persistence mechanism for WordPress malware.</strong> They auto-load on every request and survive plugin deactivation. Monitored every 5 minutes.</p>
            </div>

            <div class="linzi-section">
                <?php if (!empty($mu_plugins)) : ?>
                <table class="widefat linzi-table">
                    <thead><tr><th>File</th><th>Size</th><th>Status</th><th>First Seen</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($mu_plugins as $mu) : ?>
                        <tr class="<?php echo $mu['is_approved'] ? '' : 'linzi-threat-high'; ?>">
                            <td><code><?php echo esc_html($mu['file_name']); ?></code></td>
                            <td><?php echo esc_html(size_format($mu['file_size'])); ?></td>
                            <td>
                                <span class="linzi-severity linzi-severity-<?php echo $mu['is_approved'] ? 'low' : 'high'; ?>">
                                    <?php echo $mu['is_approved'] ? 'APPROVED' : 'UNAPPROVED'; ?>
                                </span>
                            </td>
                            <td><?php echo esc_html($mu['first_seen']); ?></td>
                            <td>
                                <?php if (!$mu['is_approved']) : ?>
                                <button class="button button-primary linzi-approve-mu-btn" data-filename="<?php echo esc_attr($mu['file_name']); ?>">Approve</button>
                                <button class="button linzi-fix-btn linzi-btn-danger" data-action="delete_mu_plugin:<?php echo esc_attr($mu['file_name']); ?>" data-confirm="Delete mu-plugin <?php echo esc_attr($mu['file_name']); ?>?">Delete</button>
                                <button class="button linzi-fix-btn" data-action="quarantine_mu_plugin:<?php echo esc_attr($mu['file_name']); ?>" data-confirm="Quarantine <?php echo esc_attr($mu['file_name']); ?>?">Quarantine</button>
                                <?php else : ?>
                                <em>Trusted</em>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                <?php else : ?>
                <div class="linzi-success-message">
                    <span class="dashicons dashicons-yes-alt" style="font-size:40px;color:#46b450;"></span>
                    <h3>No MU-Plugins Found</h3>
                    <p>Clean. Monitoring active.</p>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }

    public function render_activity() {
        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-list-view"></span> Activity Log</h1>
            <div class="linzi-section" id="linzi-activity-container">
                <div class="linzi-loading">Loading...</div>
            </div>
        </div>
        <?php
    }

    public function render_hardening() {
        $linzi = LinziContinue::instance();
        $checks = $linzi->hardening->get_hardening_status();

        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-lock"></span> Security Hardening</h1>

            <div class="linzi-section">
                <table class="widefat linzi-table">
                    <thead><tr><th>Check</th><th>Status</th><th>Impact</th><th>Action</th></tr></thead>
                    <tbody>
                    <?php foreach ($checks as $check) : ?>
                        <tr>
                            <td><strong><?php echo esc_html($check['name']); ?></strong></td>
                            <td>
                                <?php if ($check['status']) : ?>
                                <span style="color:#46b450;font-weight:bold;">&#10004; Active</span>
                                <?php else : ?>
                                <span style="color:#dc3232;font-weight:bold;">&#10008; Inactive</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($check['impact']); ?></td>
                            <td>
                                <?php if (!$check['status']) : ?>
                                <button class="button button-primary linzi-fix-btn"
                                        data-action="apply_hardening:<?php echo esc_attr(sanitize_key($check['name'])); ?>"
                                        data-confirm="Enable <?php echo esc_attr($check['name']); ?>?">
                                    Enable
                                </button>
                                <?php else : ?>
                                <em>OK</em>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    public function render_settings() {
        $options = LinziContinue::get_options();

        if (isset($_POST['linzi_save_settings']) && check_admin_referer('linzi_settings_save')) {
            $options['firewall_enabled'] = !empty($_POST['firewall_enabled']);
            $options['login_protection'] = !empty($_POST['login_protection']);
            $options['file_monitoring'] = !empty($_POST['file_monitoring']);
            $options['mu_monitoring'] = !empty($_POST['mu_monitoring']);
            $options['hardening_enabled'] = !empty($_POST['hardening_enabled']);
            $options['activity_logging'] = !empty($_POST['activity_logging']);
            $options['email_alerts'] = sanitize_email($_POST['email_alerts'] ?? '');
            $options['max_login_attempts'] = absint($_POST['max_login_attempts'] ?? 5);
            $options['lockout_duration'] = absint($_POST['lockout_duration'] ?? 1800);
            $options['auto_quarantine'] = !empty($_POST['auto_quarantine']);
            $options['disable_xmlrpc'] = !empty($_POST['disable_xmlrpc']);
            $options['disable_file_editor'] = !empty($_POST['disable_file_editor']);
            $options['hide_wp_version'] = !empty($_POST['hide_wp_version']);
            $options['blocked_ips'] = array_filter(array_map('sanitize_text_field', explode("\n", $_POST['blocked_ips'] ?? '')));
            $options['whitelisted_ips'] = array_filter(array_map('sanitize_text_field', explode("\n", $_POST['whitelisted_ips'] ?? '')));

            update_option('linzi_options', $options);
            echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
        }

        ?>
        <div class="wrap linzi-wrap">
            <h1><span class="dashicons dashicons-admin-generic"></span> Settings</h1>
            <form method="post">
                <?php wp_nonce_field('linzi_settings_save'); ?>
                <div class="linzi-section">
                    <h2>Modules</h2>
                    <table class="form-table">
                        <tr><th>Firewall</th><td><label><input type="checkbox" name="firewall_enabled" <?php checked($options['firewall_enabled']); ?>> WAF (SQL injection, XSS, etc.)</label></td></tr>
                        <tr><th>Login Protection</th><td><label><input type="checkbox" name="login_protection" <?php checked($options['login_protection']); ?>> Brute force protection</label></td></tr>
                        <tr><th>File Monitoring</th><td><label><input type="checkbox" name="file_monitoring" <?php checked($options['file_monitoring']); ?>> Hourly integrity checks</label></td></tr>
                        <tr><th>MU Guard</th><td><label><input type="checkbox" name="mu_monitoring" <?php checked($options['mu_monitoring']); ?>> MU-plugins monitoring (5 min) <strong>CRITICAL</strong></label></td></tr>
                        <tr><th>Hardening</th><td><label><input type="checkbox" name="hardening_enabled" <?php checked($options['hardening_enabled']); ?>> Security hardening</label></td></tr>
                        <tr><th>Logging</th><td><label><input type="checkbox" name="activity_logging" <?php checked($options['activity_logging']); ?>> Activity logging</label></td></tr>
                    </table>
                </div>
                <div class="linzi-section">
                    <h2>Login</h2>
                    <table class="form-table">
                        <tr><th>Max Attempts</th><td><input type="number" name="max_login_attempts" value="<?php echo esc_attr($options['max_login_attempts']); ?>" min="1" max="20" class="small-text"> before lockout</td></tr>
                        <tr><th>Lockout</th><td><input type="number" name="lockout_duration" value="<?php echo esc_attr($options['lockout_duration']); ?>" min="60" max="86400" class="small-text"> seconds</td></tr>
                    </table>
                </div>
                <div class="linzi-section">
                    <h2>Hardening</h2>
                    <table class="form-table">
                        <tr><th>XML-RPC</th><td><label><input type="checkbox" name="disable_xmlrpc" <?php checked($options['disable_xmlrpc']); ?>> Disable</label></td></tr>
                        <tr><th>File Editor</th><td><label><input type="checkbox" name="disable_file_editor" <?php checked($options['disable_file_editor']); ?>> Disable</label></td></tr>
                        <tr><th>WP Version</th><td><label><input type="checkbox" name="hide_wp_version" <?php checked($options['hide_wp_version']); ?>> Hide</label></td></tr>
                        <tr><th>Auto-Quarantine</th><td><label><input type="checkbox" name="auto_quarantine" <?php checked($options['auto_quarantine']); ?>> Auto-quarantine critical threats</label></td></tr>
                    </table>
                </div>
                <div class="linzi-section">
                    <h2>Alerts & IPs</h2>
                    <table class="form-table">
                        <tr><th>Alert Email</th><td><input type="email" name="email_alerts" value="<?php echo esc_attr($options['email_alerts']); ?>" class="regular-text"></td></tr>
                        <tr><th>Blocked IPs</th><td><textarea name="blocked_ips" rows="4" class="large-text"><?php echo esc_textarea(implode("\n", $options['blocked_ips'])); ?></textarea></td></tr>
                        <tr><th>Whitelisted IPs</th><td><textarea name="whitelisted_ips" rows="4" class="large-text"><?php echo esc_textarea(implode("\n", $options['whitelisted_ips'])); ?></textarea></td></tr>
                    </table>
                </div>
                <p class="submit"><input type="submit" name="linzi_save_settings" class="button button-primary button-hero" value="Save Settings"></p>
            </form>
        </div>
        <?php
    }
}
