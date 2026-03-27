<?php
if (!defined('ABSPATH')) exit;

class Linzi_File_Monitor {

    public function __construct() {
        // Hook into plugin/theme activation/deactivation
        add_action('activated_plugin', [$this, 'on_plugin_change']);
        add_action('deactivated_plugin', [$this, 'on_plugin_change']);
        add_action('switch_theme', [$this, 'on_theme_change']);
        add_action('upgrader_process_complete', [$this, 'on_update_complete']);
    }

    public function take_snapshot() {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_file_hashes';

        // Clear existing snapshot
        $wpdb->query("TRUNCATE TABLE $table");

        // Snapshot WordPress core files
        $this->snapshot_directory(ABSPATH, 'core', ['wp-content']);

        // Snapshot plugins
        $this->snapshot_directory(WP_PLUGIN_DIR, 'plugin');

        // Snapshot mu-plugins
        if (is_dir(WPMU_PLUGIN_DIR)) {
            $this->snapshot_directory(WPMU_PLUGIN_DIR, 'mu-plugin');
        }

        // Snapshot active theme
        $this->snapshot_directory(get_stylesheet_directory(), 'theme');

        update_option('linzi_last_snapshot', current_time('mysql'));
    }

    private function snapshot_directory($dir, $type, $exclude_dirs = []) {
        global $wpdb;

        if (!is_dir($dir)) return;

        // Always exclude these directories (nested WP installs, version control, etc.)
        $always_exclude = ['node_modules', '.git', '.svn', 'vendor', 'cache', 'backups', 'upgrade'];

        // Detect nested WordPress installations and exclude them
        $scan_dirs = @scandir($dir);
        if ($scan_dirs) {
            foreach ($scan_dirs as $subdir) {
                if ($subdir === '.' || $subdir === '..') continue;
                $subpath = $dir . DIRECTORY_SEPARATOR . $subdir;
                if (is_dir($subpath) && file_exists($subpath . DIRECTORY_SEPARATOR . 'wp-config.php')) {
                    $always_exclude[] = $subdir;
                }
            }
        }

        $exclude_dirs = array_merge($exclude_dirs, $always_exclude);

        $iterator = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                function ($current) use ($exclude_dirs) {
                    if ($current->isDir()) {
                        return !in_array($current->getFilename(), $exclude_dirs);
                    }
                    return true;
                }
            )
        );

        $batch = [];
        $batch_size = 50; // Smaller batches to avoid deadlocks

        foreach ($iterator as $file) {
            if ($file->isDir()) continue;

            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['php', 'js', 'css', 'html', 'htm', 'htaccess'])) continue;

            $filepath = $file->getPathname();

            $batch[] = $wpdb->prepare(
                "(%s, %s, %d, %s, %s)",
                wp_normalize_path($filepath),
                hash_file('sha256', $filepath),
                $file->getSize(),
                gmdate('Y-m-d H:i:s', $file->getMTime()),
                $type
            );

            if (count($batch) >= $batch_size) {
                $this->insert_batch($batch);
                $batch = [];
            }
        }

        if (!empty($batch)) {
            $this->insert_batch($batch);
        }
    }

    private function insert_batch($batch) {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_file_hashes';

        $query = "INSERT INTO $table (file_path, file_hash, file_size, file_modified, snapshot_type) VALUES ";
        $query .= implode(', ', $batch);
        $query .= " ON DUPLICATE KEY UPDATE file_hash = VALUES(file_hash), file_size = VALUES(file_size), file_modified = VALUES(file_modified)";

        // Retry on deadlock (up to 3 attempts)
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $result = $wpdb->query($query);
            if ($result !== false) return;

            // Check if it's a deadlock error
            $error = $wpdb->last_error;
            if (stripos($error, 'deadlock') === false) return; // Non-deadlock error, don't retry

            if ($attempt < 3) {
                usleep(100000 * $attempt); // 100ms, 200ms backoff
            }
        }
    }

    public function check_integrity() {
        global $wpdb;
        $table = $wpdb->prefix . 'linzi_file_hashes';

        $options = LinziContinue::get_options();
        if (empty($options['file_monitoring'])) return;

        $changes = [
            'modified' => [],
            'deleted'  => [],
            'new'      => [],
        ];

        // Get all stored hashes
        $stored = $wpdb->get_results("SELECT * FROM $table", ARRAY_A);

        foreach ($stored as $record) {
            $filepath = $record['file_path'];

            if (!file_exists($filepath)) {
                $changes['deleted'][] = [
                    'file_path'     => $filepath,
                    'snapshot_type' => $record['snapshot_type'],
                    'original_hash' => $record['file_hash'],
                ];
                continue;
            }

            $current_hash = hash_file('sha256', $filepath);
            if ($current_hash !== $record['file_hash']) {
                $changes['modified'][] = [
                    'file_path'     => $filepath,
                    'snapshot_type' => $record['snapshot_type'],
                    'original_hash' => $record['file_hash'],
                    'current_hash'  => $current_hash,
                    'original_size' => $record['file_size'],
                    'current_size'  => filesize($filepath),
                ];
            }
        }

        // Check for new files in monitored directories
        $dirs_to_check = [
            WP_PLUGIN_DIR  => 'plugin',
            WPMU_PLUGIN_DIR => 'mu-plugin',
        ];

        foreach ($dirs_to_check as $dir => $type) {
            if (!is_dir($dir)) continue;

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if ($file->isDir()) continue;
                $ext = strtolower($file->getExtension());
                if (!in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5'])) continue;

                $filepath = wp_normalize_path($file->getPathname());

                // Skip our own files
                if (strpos($filepath, 'linzicontinue') !== false) continue;

                $exists = $wpdb->get_var($wpdb->prepare(
                    "SELECT COUNT(*) FROM $table WHERE file_path = %s",
                    $filepath
                ));

                if (!$exists) {
                    $changes['new'][] = [
                        'file_path'     => $filepath,
                        'snapshot_type' => $type,
                        'current_hash'  => hash_file('sha256', $filepath),
                        'current_size'  => $file->getSize(),
                        'created_at'    => gmdate('Y-m-d H:i:s', $file->getCTime()),
                    ];
                }
            }
        }

        // Report changes
        $total_changes = count($changes['modified']) + count($changes['deleted']) + count($changes['new']);

        if ($total_changes > 0) {
            // Log to activity log
            if (class_exists('Linzi_Activity_Log')) {
                $log = new Linzi_Activity_Log();
                $severity = !empty($changes['new']) || !empty($changes['modified']) ? 'warning' : 'info';
                $log->log('file_integrity_change', $severity, sprintf(
                    'File integrity check: %d modified, %d deleted, %d new files detected',
                    count($changes['modified']),
                    count($changes['deleted']),
                    count($changes['new'])
                ), $changes);
            }

            // Send email alert for critical changes
            if (!empty($changes['new']) || count($changes['modified']) > 5) {
                $this->send_integrity_alert($changes);
            }

            // Store change report
            update_option('linzi_last_integrity_check', [
                'time'    => current_time('mysql'),
                'changes' => $changes,
                'total'   => $total_changes,
            ]);
        }

        return $changes;
    }

    private function send_integrity_alert($changes) {
        $options = LinziContinue::get_options();
        $email = $options['email_alerts'];
        if (empty($email)) return;

        $subject = sprintf(
            '[Linzi] File integrity changes detected on %s',
            get_bloginfo('name')
        );

        $body = sprintf(
            "File integrity monitoring has detected changes.\n\n" .
            "Site: %s\n" .
            "Modified files: %d\n" .
            "Deleted files: %d\n" .
            "New files: %d\n\n",
            get_site_url(),
            count($changes['modified']),
            count($changes['deleted']),
            count($changes['new'])
        );

        if (!empty($changes['new'])) {
            $body .= "=== NEW FILES (INVESTIGATE) ===\n";
            foreach ($changes['new'] as $f) {
                $body .= "  " . $f['file_path'] . " (size: " . size_format($f['current_size']) . ")\n";
            }
            $body .= "\n";
        }

        if (!empty($changes['modified'])) {
            $body .= "=== MODIFIED FILES ===\n";
            foreach (array_slice($changes['modified'], 0, 20) as $f) {
                $body .= "  " . $f['file_path'] . "\n";
            }
            if (count($changes['modified']) > 20) {
                $body .= "  ... and " . (count($changes['modified']) - 20) . " more\n";
            }
            $body .= "\n";
        }

        $body .= "Log in to review: " . admin_url('admin.php?page=linzicontinue') . "\n";

        wp_mail($email, $subject, $body);
    }

    public function on_plugin_change($plugin) {
        // After plugin activation/deactivation, update snapshot
        $this->snapshot_directory(WP_PLUGIN_DIR, 'plugin');
    }

    public function on_theme_change() {
        $this->snapshot_directory(get_stylesheet_directory(), 'theme');
    }

    public function on_update_complete($upgrader) {
        // Re-snapshot after WordPress/plugin/theme updates
        wp_schedule_single_event(time() + 30, 'linzi_post_update_snapshot');
        add_action('linzi_post_update_snapshot', function () {
            $monitor = new Linzi_File_Monitor();
            $monitor->take_snapshot();
        });
    }

    public function get_monitored_count() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->prefix}linzi_file_hashes"
        );
    }
}
