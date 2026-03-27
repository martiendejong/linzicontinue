<?php
if (!defined('ABSPATH')) exit;

class Linzi_Database {

    public function create_tables() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = [];

        // Activity log table
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_activity_log (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'info',
            user_id BIGINT UNSIGNED DEFAULT 0,
            ip_address VARCHAR(45),
            user_agent TEXT,
            description TEXT NOT NULL,
            details LONGTEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY severity (severity),
            KEY created_at (created_at),
            KEY ip_address (ip_address)
        ) $charset_collate;";

        // Threats table
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_threats (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path TEXT NOT NULL,
            threat_type VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'medium',
            signature VARCHAR(255),
            description TEXT,
            file_hash VARCHAR(64),
            status VARCHAR(20) NOT NULL DEFAULT 'detected',
            detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            KEY threat_type (threat_type),
            KEY severity (severity),
            KEY status (status)
        ) $charset_collate;";

        // Login attempts table
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_login_attempts (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            username VARCHAR(255),
            success TINYINT(1) NOT NULL DEFAULT 0,
            attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempted_at (attempted_at)
        ) $charset_collate;";

        // IP lockouts table
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_lockouts (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            reason VARCHAR(255),
            locked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            permanent TINYINT(1) NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        // Firewall log table
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_firewall_log (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            request_uri TEXT,
            request_method VARCHAR(10),
            rule_matched VARCHAR(100),
            action_taken VARCHAR(50) NOT NULL DEFAULT 'blocked',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY rule_matched (rule_matched),
            KEY created_at (created_at)
        ) $charset_collate;";

        // File integrity snapshots
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_file_hashes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path VARCHAR(500) NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
            file_modified DATETIME,
            snapshot_type VARCHAR(20) NOT NULL DEFAULT 'core',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY file_path (file_path(400)),
            KEY snapshot_type (snapshot_type)
        ) $charset_collate;";

        // MU-plugins registry
        $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}linzi_mu_registry (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            file_name VARCHAR(255) NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
            is_approved TINYINT(1) NOT NULL DEFAULT 0,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_checked DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY file_name (file_name)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        foreach ($sql as $query) {
            dbDelta($query);
        }

        update_option('linzi_db_version', LINZI_VERSION);
    }

    public function cleanup_old_logs($days = 90) {
        global $wpdb;
        $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));

        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}linzi_activity_log WHERE created_at < %s",
            $cutoff
        ));

        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}linzi_firewall_log WHERE created_at < %s",
            $cutoff
        ));

        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}linzi_login_attempts WHERE attempted_at < %s",
            $cutoff
        ));
    }
}
