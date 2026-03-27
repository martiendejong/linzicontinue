<?php
if (!defined('ABSPATH')) exit;

class Linzi_Activity_Log {

    public function __construct() {
        $options = LinziContinue::get_options();
        if (empty($options['activity_logging'])) return;

        // Track admin actions
        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_action('wp_logout', [$this, 'log_logout']);
        add_action('user_register', [$this, 'log_user_created']);
        add_action('delete_user', [$this, 'log_user_deleted']);
        add_action('profile_update', [$this, 'log_profile_update']);
        add_action('set_user_role', [$this, 'log_role_change'], 10, 3);

        // Track content changes
        add_action('save_post', [$this, 'log_post_change'], 10, 3);
        add_action('delete_post', [$this, 'log_post_deleted']);

        // Track plugin changes
        add_action('activated_plugin', [$this, 'log_plugin_activated']);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivated']);
        add_action('deleted_plugin', [$this, 'log_plugin_deleted'], 10, 2);

        // Track theme changes
        add_action('switch_theme', [$this, 'log_theme_changed'], 10, 3);

        // Track option changes (critical ones)
        add_action('update_option_siteurl', [$this, 'log_siteurl_change'], 10, 2);
        add_action('update_option_home', [$this, 'log_home_change'], 10, 2);
        add_action('update_option_admin_email', [$this, 'log_admin_email_change'], 10, 2);
        add_action('update_option_users_can_register', [$this, 'log_registration_change'], 10, 2);
        add_action('update_option_default_role', [$this, 'log_default_role_change'], 10, 2);

        // Track file uploads
        add_filter('wp_handle_upload', [$this, 'log_file_upload']);

        // Track core updates
        add_action('_core_updated_successfully', [$this, 'log_core_update']);

        // Periodic cleanup
        add_action('linzi_cleanup_logs', [$this, 'cleanup_old_logs']);
        if (!wp_next_scheduled('linzi_cleanup_logs')) {
            wp_schedule_event(time(), 'weekly', 'linzi_cleanup_logs');
        }
    }

    public function log($event_type, $severity, $description, $details = null) {
        global $wpdb;

        $wpdb->insert($wpdb->prefix . 'linzi_activity_log', [
            'event_type'  => $event_type,
            'severity'    => $severity,
            'user_id'     => get_current_user_id(),
            'ip_address'  => $this->get_client_ip(),
            'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 500) : '',
            'description' => $description,
            'details'     => $details ? wp_json_encode($details) : null,
            'created_at'  => current_time('mysql'),
        ]);
    }

    // === Login/Logout Tracking ===

    public function log_login($username, $user) {
        $this->log('user_login', 'info', sprintf('User logged in: %s', $username));
    }

    public function log_logout() {
        $user = wp_get_current_user();
        if ($user->ID) {
            $this->log('user_logout', 'info', sprintf('User logged out: %s', $user->user_login));
        }
    }

    // === User Management ===

    public function log_user_created($user_id) {
        $user = get_userdata($user_id);
        $severity = in_array('administrator', $user->roles) ? 'warning' : 'info';
        $this->log('user_created', $severity, sprintf(
            'New user created: %s (role: %s, email: %s)',
            $user->user_login,
            implode(', ', $user->roles),
            $user->user_email
        ));
    }

    public function log_user_deleted($user_id) {
        $user = get_userdata($user_id);
        $name = $user ? $user->user_login : "ID:$user_id";
        $this->log('user_deleted', 'warning', sprintf('User deleted: %s', $name));
    }

    public function log_profile_update($user_id) {
        $user = get_userdata($user_id);
        $this->log('profile_updated', 'info', sprintf('Profile updated: %s', $user->user_login));
    }

    public function log_role_change($user_id, $role, $old_roles) {
        $user = get_userdata($user_id);
        $severity = ($role === 'administrator') ? 'critical' : 'warning';
        $this->log('role_changed', $severity, sprintf(
            'User role changed: %s from [%s] to [%s]',
            $user->user_login,
            implode(', ', $old_roles),
            $role
        ));
    }

    // === Content Changes ===

    public function log_post_change($post_id, $post, $update) {
        if (wp_is_post_revision($post_id) || wp_is_post_autosave($post_id)) return;
        if ($post->post_status === 'auto-draft') return;

        $action = $update ? 'updated' : 'created';
        $this->log('post_' . $action, 'info', sprintf(
            '%s %s: "%s" (ID: %d, type: %s)',
            ucfirst($post->post_type),
            $action,
            $post->post_title,
            $post_id,
            $post->post_type
        ));
    }

    public function log_post_deleted($post_id) {
        $post = get_post($post_id);
        if (!$post || $post->post_type === 'revision') return;

        $this->log('post_deleted', 'info', sprintf(
            '%s deleted: "%s" (ID: %d)',
            ucfirst($post->post_type),
            $post->post_title,
            $post_id
        ));
    }

    // === Plugin/Theme Changes ===

    public function log_plugin_activated($plugin) {
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
        $this->log('plugin_activated', 'info', sprintf(
            'Plugin activated: %s v%s',
            $plugin_data['Name'] ?: $plugin,
            $plugin_data['Version'] ?: 'unknown'
        ));
    }

    public function log_plugin_deactivated($plugin) {
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
        $this->log('plugin_deactivated', 'info', sprintf(
            'Plugin deactivated: %s',
            $plugin_data['Name'] ?: $plugin
        ));
    }

    public function log_plugin_deleted($plugin, $deleted) {
        $this->log('plugin_deleted', 'warning', sprintf('Plugin deleted: %s', $plugin));
    }

    public function log_theme_changed($new_name, $new_theme, $old_theme) {
        $this->log('theme_changed', 'info', sprintf(
            'Theme changed from "%s" to "%s"',
            $old_theme->get('Name'),
            $new_name
        ));
    }

    // === Critical Setting Changes ===

    public function log_siteurl_change($old, $new) {
        $this->log('setting_changed', 'critical', sprintf(
            'Site URL changed from "%s" to "%s"',
            $old,
            $new
        ));
    }

    public function log_home_change($old, $new) {
        $this->log('setting_changed', 'critical', sprintf(
            'Home URL changed from "%s" to "%s"',
            $old,
            $new
        ));
    }

    public function log_admin_email_change($old, $new) {
        $this->log('setting_changed', 'critical', sprintf(
            'Admin email changed from "%s" to "%s"',
            $old,
            $new
        ));
    }

    public function log_registration_change($old, $new) {
        $this->log('setting_changed', 'warning', sprintf(
            'User registration %s',
            $new ? 'ENABLED' : 'disabled'
        ));
    }

    public function log_default_role_change($old, $new) {
        $severity = ($new === 'administrator') ? 'critical' : 'warning';
        $this->log('setting_changed', $severity, sprintf(
            'Default user role changed from "%s" to "%s"',
            $old,
            $new
        ));
    }

    // === File Uploads ===

    public function log_file_upload($upload) {
        if (isset($upload['file'])) {
            $this->log('file_uploaded', 'info', sprintf(
                'File uploaded: %s (type: %s)',
                basename($upload['file']),
                $upload['type'] ?? 'unknown'
            ));
        }
        return $upload;
    }

    // === Core Updates ===

    public function log_core_update($wp_version) {
        $this->log('core_updated', 'info', sprintf('WordPress updated to version %s', $wp_version));
    }

    // === Log Retrieval ===

    public function get_logs($page = 1, $per_page = 50) {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_activity_log';
        $offset = ($page - 1) * $per_page;

        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table");
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT l.*, u.user_login
             FROM $table l
             LEFT JOIN {$wpdb->users} u ON l.user_id = u.ID
             ORDER BY l.created_at DESC
             LIMIT %d OFFSET %d",
            $per_page,
            $offset
        ), ARRAY_A);

        return [
            'logs'     => $logs,
            'total'    => $total,
            'page'     => $page,
            'per_page' => $per_page,
            'pages'    => ceil($total / $per_page),
        ];
    }

    public function cleanup_old_logs() {
        $db = new Linzi_Database();
        $db->cleanup_old_logs(90);
    }

    private function get_client_ip() {
        $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
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
}
