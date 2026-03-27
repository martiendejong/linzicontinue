<?php
if (!defined('ABSPATH')) exit;

class Linzi_Login_Security {

    public function __construct() {
        $options = LinziContinue::get_options();
        if (empty($options['login_protection'])) return;

        add_filter('authenticate', [$this, 'check_login_attempt'], 30, 3);
        add_action('wp_login', [$this, 'on_successful_login'], 10, 2);
        add_action('wp_login_failed', [$this, 'on_failed_login']);
        add_filter('login_errors', [$this, 'hide_login_errors']);

        // Track login page access
        add_action('login_init', [$this, 'track_login_page_access']);
    }

    public function check_login_attempt($user, $username, $password) {
        if (empty($username)) return $user;

        $ip = $this->get_client_ip();
        $options = LinziContinue::get_options();

        // Check if IP is locked out
        if ($this->is_locked_out($ip)) {
            return new WP_Error(
                'linzi_lockout',
                sprintf(
                    __('Too many failed login attempts. Please try again in %d minutes.', 'linzicontinue'),
                    ceil($options['lockout_duration'] / 60)
                )
            );
        }

        // Check if username exists (prevent user enumeration via timing)
        // We still process the authentication but track the attempt

        return $user;
    }

    public function on_successful_login($username, $user) {
        $ip = $this->get_client_ip();

        // Log successful login
        $this->log_attempt($ip, $username, true);

        // Clear failed attempts for this IP
        $this->clear_failed_attempts($ip);

        // Update user's last login time
        update_user_meta($user->ID, 'last_login', current_time('mysql'));
        update_user_meta($user->ID, 'last_login_ip', $ip);

        // Log to activity log
        if (class_exists('Linzi_Activity_Log')) {
            $log = new Linzi_Activity_Log();
            $log->log('login_success', 'info', sprintf(
                'Successful login: %s from %s',
                $username,
                $ip
            ));
        }

        // Check if this is a new IP for admin accounts
        if (in_array('administrator', $user->roles)) {
            $known_ips = get_user_meta($user->ID, 'linzi_known_ips', true);
            if (!is_array($known_ips)) $known_ips = [];

            if (!in_array($ip, $known_ips)) {
                // New IP for admin - send alert
                $this->send_new_admin_ip_alert($user, $ip);

                // Add to known IPs
                $known_ips[] = $ip;
                update_user_meta($user->ID, 'linzi_known_ips', array_slice($known_ips, -20));
            }
        }
    }

    public function on_failed_login($username) {
        $ip = $this->get_client_ip();

        // Log failed attempt
        $this->log_attempt($ip, $username, false);

        // Count recent failures
        $failures = $this->count_recent_failures($ip);
        $options = LinziContinue::get_options();
        $max_attempts = $options['max_login_attempts'];

        if ($failures >= $max_attempts) {
            $this->create_lockout($ip, 'Too many failed login attempts (' . $failures . ')');

            // Log to activity log
            if (class_exists('Linzi_Activity_Log')) {
                $log = new Linzi_Activity_Log();
                $log->log('login_lockout', 'warning', sprintf(
                    'IP %s locked out after %d failed attempts (last username: %s)',
                    $ip,
                    $failures,
                    $username
                ));
            }

            // If > 3x max attempts, send email alert
            if ($failures >= $max_attempts * 3) {
                $this->send_brute_force_alert($ip, $username, $failures);
            }
        }
    }

    public function hide_login_errors($error) {
        // Don't reveal whether username exists or password is wrong
        return __('Invalid username or password.', 'linzicontinue');
    }

    public function track_login_page_access() {
        $ip = $this->get_client_ip();

        // Log login page access (for detecting automated scanners)
        if (class_exists('Linzi_Activity_Log')) {
            $log = new Linzi_Activity_Log();
            $log->log('login_page_access', 'info', 'Login page accessed from ' . $ip);
        }
    }

    private function log_attempt($ip, $username, $success) {
        global $wpdb;
        $wpdb->insert($wpdb->prefix . 'linzi_login_attempts', [
            'ip_address'   => $ip,
            'username'     => sanitize_user($username),
            'success'      => $success ? 1 : 0,
            'attempted_at' => current_time('mysql'),
        ]);
    }

    private function count_recent_failures($ip) {
        global $wpdb;
        $options = LinziContinue::get_options();
        $window = $options['lockout_duration'];

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_login_attempts
             WHERE ip_address = %s AND success = 0
             AND attempted_at > DATE_SUB(NOW(), INTERVAL %d SECOND)",
            $ip,
            $window
        ));
    }

    private function clear_failed_attempts($ip) {
        global $wpdb;
        $wpdb->delete($wpdb->prefix . 'linzi_login_attempts', [
            'ip_address' => $ip,
            'success'    => 0,
        ]);
    }

    private function is_locked_out($ip) {
        global $wpdb;
        return (bool) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_lockouts
             WHERE ip_address = %s AND (expires_at > NOW() OR permanent = 1)",
            $ip
        ));
    }

    private function create_lockout($ip, $reason) {
        global $wpdb;
        $options = LinziContinue::get_options();

        $wpdb->insert($wpdb->prefix . 'linzi_lockouts', [
            'ip_address' => $ip,
            'reason'     => $reason,
            'locked_at'  => current_time('mysql'),
            'expires_at' => gmdate('Y-m-d H:i:s', time() + $options['lockout_duration']),
        ]);
    }

    private function send_new_admin_ip_alert($user, $ip) {
        $options = LinziContinue::get_options();
        $email = $options['email_alerts'];
        if (empty($email)) return;

        $subject = sprintf(
            '[Linzi] New admin login IP detected on %s',
            get_bloginfo('name')
        );

        $body = sprintf(
            "A WordPress administrator logged in from a new IP address.\n\n" .
            "Username: %s\n" .
            "IP Address: %s\n" .
            "Time: %s\n" .
            "Site: %s\n\n" .
            "If this was not you, change your password immediately and check for unauthorized changes.\n",
            $user->user_login,
            $ip,
            current_time('mysql'),
            get_site_url()
        );

        wp_mail($email, $subject, $body);
    }

    private function send_brute_force_alert($ip, $last_username, $attempts) {
        $options = LinziContinue::get_options();
        $email = $options['email_alerts'];
        if (empty($email)) return;

        $subject = sprintf(
            '[Linzi] Brute force attack detected on %s',
            get_bloginfo('name')
        );

        $body = sprintf(
            "A possible brute force attack has been detected.\n\n" .
            "Attacker IP: %s\n" .
            "Total attempts: %d\n" .
            "Last username tried: %s\n" .
            "Time: %s\n" .
            "Site: %s\n\n" .
            "The IP has been temporarily locked out.\n" .
            "Consider permanently blocking this IP in Linzi settings.\n",
            $ip,
            $attempts,
            $last_username,
            current_time('mysql'),
            get_site_url()
        );

        wp_mail($email, $subject, $body);
    }

    public function get_failed_count() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_login_attempts WHERE success = 0"
        );
    }

    public function get_active_lockouts() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_lockouts
             WHERE expires_at > NOW() OR permanent = 1"
        );
    }

    public function get_recent_attempts($limit = 50) {
        global $wpdb;
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}linzi_login_attempts
             ORDER BY attempted_at DESC LIMIT %d",
            $limit
        ), ARRAY_A);
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
