<?php
/**
 * Plugin Name: Linzi Security
 * Plugin URI: https://linzicontinue.com
 * Description: Advanced WordPress security suite - firewall, malware scanner, login protection, file integrity monitoring, mu-plugins guardian, and real-time threat dashboard. Built from real-world breach forensics.
 * Version: 1.0.0
 * Author: Promotiemeester
 * Author URI: https://promotiemeester.nl
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: linzicontinue
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('LINZI_VERSION', '1.0.0');
define('LINZI_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('LINZI_PLUGIN_URL', plugin_dir_url(__FILE__));
define('LINZI_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Load core classes
require_once LINZI_PLUGIN_DIR . 'includes/class-database.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-scanner.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-firewall.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-login-security.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-file-monitor.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-mu-monitor.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-hardening.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-activity-log.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-fixer.php';
require_once LINZI_PLUGIN_DIR . 'includes/class-dashboard.php';

final class LinziContinue {

    private static $instance = null;

    public $scanner;
    public $firewall;
    public $login_security;
    public $file_monitor;
    public $mu_monitor;
    public $hardening;
    public $activity_log;
    public $dashboard;
    public $fixer;
    public $db;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->db = new Linzi_Database();
        $this->scanner = new Linzi_Scanner();
        $this->firewall = new Linzi_Firewall();
        $this->login_security = new Linzi_Login_Security();
        $this->file_monitor = new Linzi_File_Monitor();
        $this->mu_monitor = new Linzi_MU_Monitor();
        $this->hardening = new Linzi_Hardening();
        $this->activity_log = new Linzi_Activity_Log();
        $this->fixer = new Linzi_Fixer();

        if (is_admin()) {
            $this->dashboard = new Linzi_Dashboard();
        }

        // Fire early firewall checks (before WordPress fully loads)
        $this->firewall->init();

        add_action('init', [$this, 'init']);
        add_action('admin_init', [$this, 'admin_init']);

        // Cron events for scheduled scans
        add_action('linzi_scheduled_scan', [$this->scanner, 'run_full_scan']);
        add_action('linzi_scheduled_file_check', [$this->file_monitor, 'check_integrity']);
        add_action('linzi_scheduled_mu_check', [$this->mu_monitor, 'check_mu_plugins']);

        // REST API
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    public function init() {
        // Schedule cron events if not already scheduled
        if (!wp_next_scheduled('linzi_scheduled_scan')) {
            wp_schedule_event(time(), 'twicedaily', 'linzi_scheduled_scan');
        }
        if (!wp_next_scheduled('linzi_scheduled_file_check')) {
            wp_schedule_event(time(), 'hourly', 'linzi_scheduled_file_check');
        }
        if (!wp_next_scheduled('linzi_scheduled_mu_check')) {
            wp_schedule_event(time(), 'every_five_minutes', 'linzi_scheduled_mu_check');
        }

        // Add custom cron interval for mu-plugins check (every 5 minutes)
        add_filter('cron_schedules', function ($schedules) {
            $schedules['every_five_minutes'] = [
                'interval' => 300,
                'display'  => __('Every 5 Minutes', 'linzicontinue'),
            ];
            return $schedules;
        });
    }

    public function admin_init() {
        // Register settings
        register_setting('linzi_settings', 'linzi_options', [
            'sanitize_callback' => [$this, 'sanitize_options'],
        ]);

        // Run deferred initial snapshots (after activation)
        if (get_option('linzi_needs_initial_snapshot')) {
            delete_option('linzi_needs_initial_snapshot');

            $this->file_monitor->take_snapshot();
            $this->mu_monitor->take_snapshot();
        }
    }

    public function sanitize_options($input) {
        $sanitized = [];

        $sanitized['firewall_enabled'] = !empty($input['firewall_enabled']);
        $sanitized['login_protection'] = !empty($input['login_protection']);
        $sanitized['file_monitoring'] = !empty($input['file_monitoring']);
        $sanitized['mu_monitoring'] = !empty($input['mu_monitoring']);
        $sanitized['hardening_enabled'] = !empty($input['hardening_enabled']);
        $sanitized['activity_logging'] = !empty($input['activity_logging']);
        $sanitized['scan_depth'] = in_array($input['scan_depth'] ?? 'standard', ['quick', 'standard', 'deep']) ? $input['scan_depth'] : 'standard';
        $sanitized['email_alerts'] = sanitize_email($input['email_alerts'] ?? '');
        $sanitized['max_login_attempts'] = absint($input['max_login_attempts'] ?? 5);
        $sanitized['lockout_duration'] = absint($input['lockout_duration'] ?? 1800);
        $sanitized['blocked_ips'] = array_filter(array_map('sanitize_text_field', explode("\n", $input['blocked_ips'] ?? '')));
        $sanitized['whitelisted_ips'] = array_filter(array_map('sanitize_text_field', explode("\n", $input['whitelisted_ips'] ?? '')));
        $sanitized['auto_quarantine'] = !empty($input['auto_quarantine']);
        $sanitized['disable_xmlrpc'] = !empty($input['disable_xmlrpc']);
        $sanitized['disable_file_editor'] = !empty($input['disable_file_editor']);
        $sanitized['hide_wp_version'] = !empty($input['hide_wp_version']);

        return $sanitized;
    }

    public function register_rest_routes() {
        register_rest_route('linzicontinue/v1', '/scan', [
            'methods'             => 'POST',
            'callback'            => [$this, 'api_run_scan'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/scan/status', [
            'methods'             => 'GET',
            'callback'            => [$this, 'api_scan_status'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/threats', [
            'methods'             => 'GET',
            'callback'            => [$this, 'api_get_threats'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/quarantine', [
            'methods'             => 'POST',
            'callback'            => [$this, 'api_quarantine_file'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/activity', [
            'methods'             => 'GET',
            'callback'            => [$this, 'api_get_activity'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/stats', [
            'methods'             => 'GET',
            'callback'            => [$this, 'api_get_stats'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);

        register_rest_route('linzicontinue/v1', '/hardening', [
            'methods'             => 'POST',
            'callback'            => [$this, 'api_apply_hardening'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            },
        ]);
    }

    public function api_run_scan($request) {
        $type = $request->get_param('type') ?? 'standard';
        $results = $this->scanner->run_full_scan($type);
        return new WP_REST_Response($results, 200);
    }

    public function api_scan_status() {
        return new WP_REST_Response($this->scanner->get_scan_status(), 200);
    }

    public function api_get_threats() {
        return new WP_REST_Response($this->scanner->get_threats(), 200);
    }

    public function api_quarantine_file($request) {
        $file = $request->get_param('file');
        if (!$file) {
            return new WP_REST_Response(['error' => 'No file specified'], 400);
        }
        $result = $this->scanner->quarantine_file($file);
        return new WP_REST_Response($result, $result['success'] ? 200 : 500);
    }

    public function api_get_activity($request) {
        $page = absint($request->get_param('page') ?? 1);
        $per_page = absint($request->get_param('per_page') ?? 50);
        return new WP_REST_Response($this->activity_log->get_logs($page, $per_page), 200);
    }

    public function api_get_stats() {
        return new WP_REST_Response([
            'blocked_attacks'    => $this->firewall->get_blocked_count(),
            'threats_found'      => $this->scanner->get_threat_count(),
            'failed_logins'      => $this->login_security->get_failed_count(),
            'files_monitored'    => $this->file_monitor->get_monitored_count(),
            'mu_plugins'         => $this->mu_monitor->get_mu_plugin_count(),
            'last_scan'          => get_option('linzi_last_scan_time', 'Never'),
            'security_score'     => $this->calculate_security_score(),
            'active_lockouts'    => $this->login_security->get_active_lockouts(),
        ], 200);
    }

    public function api_apply_hardening($request) {
        $action = $request->get_param('action_type');
        $result = $this->hardening->apply($action);
        return new WP_REST_Response($result, $result['success'] ? 200 : 500);
    }

    public function calculate_security_score() {
        $score = 100;
        $options = get_option('linzi_options', []);

        // Deductions for missing protections
        if (empty($options['firewall_enabled'])) $score -= 15;
        if (empty($options['login_protection'])) $score -= 15;
        if (empty($options['file_monitoring'])) $score -= 10;
        if (empty($options['mu_monitoring'])) $score -= 20; // mu-plugins = critical
        if (empty($options['hardening_enabled'])) $score -= 10;
        if (empty($options['disable_xmlrpc'])) $score -= 5;
        if (empty($options['disable_file_editor'])) $score -= 10;

        // Deductions for active threats
        $threats = $this->scanner->get_threat_count();
        $score -= min(30, $threats * 10);

        // Deductions for known vulnerable plugins
        $vulnerable = $this->scanner->check_vulnerable_plugins();
        $score -= min(20, count($vulnerable) * 5);

        return max(0, $score);
    }

    public static function get_options() {
        return wp_parse_args(get_option('linzi_options', []), [
            'firewall_enabled'    => true,
            'login_protection'    => true,
            'file_monitoring'     => true,
            'mu_monitoring'       => true,
            'hardening_enabled'   => true,
            'activity_logging'    => true,
            'scan_depth'          => 'standard',
            'email_alerts'        => get_option('admin_email'),
            'max_login_attempts'  => 5,
            'lockout_duration'    => 1800,
            'blocked_ips'         => [],
            'whitelisted_ips'     => [],
            'auto_quarantine'     => false,
            'disable_xmlrpc'      => true,
            'disable_file_editor' => true,
            'hide_wp_version'     => true,
        ]);
    }
}

// Activation hook
register_activation_hook(__FILE__, function () {
    $db = new Linzi_Database();
    $db->create_tables();

    // Set default options
    if (!get_option('linzi_options')) {
        update_option('linzi_options', LinziContinue::get_options());
    }

    // Create quarantine directory
    $quarantine_dir = WP_CONTENT_DIR . '/linzi-quarantine';
    if (!is_dir($quarantine_dir)) {
        wp_mkdir_p($quarantine_dir);
        file_put_contents($quarantine_dir . '/.htaccess', 'Deny from all');
        file_put_contents($quarantine_dir . '/index.php', '<?php // Silence is golden');
    }

    // Defer heavy snapshots to avoid activation timeout
    // They will run on the next page load via admin_init
    update_option('linzi_needs_initial_snapshot', true);

    // Flush rewrite rules
    flush_rewrite_rules();
});

// Deactivation hook
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('linzi_scheduled_scan');
    wp_clear_scheduled_hook('linzi_scheduled_file_check');
    wp_clear_scheduled_hook('linzi_scheduled_mu_check');
});

// Boot the plugin
LinziContinue::instance();
