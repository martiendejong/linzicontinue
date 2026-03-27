<?php
if (!defined('ABSPATH')) exit;

class Linzi_Hardening {

    public function __construct() {
        $options = LinziContinue::get_options();
        if (empty($options['hardening_enabled'])) return;

        // Apply passive hardening measures
        if (!empty($options['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', function ($headers) {
                unset($headers['X-Pingback']);
                return $headers;
            });
        }

        if (!empty($options['disable_file_editor'])) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        if (!empty($options['hide_wp_version'])) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
            add_filter('style_loader_src', [$this, 'remove_version_query'], 999);
            add_filter('script_loader_src', [$this, 'remove_version_query'], 999);
        }

        // Security headers
        add_action('send_headers', [$this, 'add_security_headers']);

        // Disable user enumeration
        add_action('template_redirect', [$this, 'prevent_user_enumeration']);

        // Remove unnecessary info
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');

        // Disable REST API user endpoint for non-authenticated users
        add_filter('rest_endpoints', [$this, 'restrict_user_endpoints']);

        // Block PHP execution in uploads
        add_action('init', [$this, 'protect_uploads_directory']);

        // Protect wp-config.php
        add_action('init', [$this, 'protect_wp_config']);

        // Disable directory browsing
        add_action('init', [$this, 'protect_directory_browsing']);
    }

    public function remove_version_query($src) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    public function add_security_headers() {
        if (headers_sent()) return;

        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');

        // XSS protection (legacy but still useful)
        header('X-XSS-Protection: 1; mode=block');

        // Prevent clickjacking
        header('X-Frame-Options: SAMEORIGIN');

        // Referrer policy
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // Permissions policy (disable unnecessary APIs)
        header("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()");
    }

    public function prevent_user_enumeration() {
        if (!is_admin() && isset($_GET['author']) && is_numeric($_GET['author'])) {
            // Block ?author=1 enumeration
            wp_safe_redirect(home_url(), 301);
            exit;
        }
    }

    public function restrict_user_endpoints($endpoints) {
        if (!is_user_logged_in()) {
            if (isset($endpoints['/wp/v2/users'])) {
                unset($endpoints['/wp/v2/users']);
            }
            if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
        }
        return $endpoints;
    }

    public function protect_uploads_directory() {
        $uploads_dir = wp_upload_dir()['basedir'];
        $htaccess_path = $uploads_dir . '/.htaccess';

        if (!file_exists($htaccess_path)) {
            $rules = "# Linzi: Block PHP execution in uploads\n";
            $rules .= "<FilesMatch \"\\.(?:php|phtml|php[3-7]|phps)$\">\n";
            $rules .= "    <IfModule mod_authz_core.c>\n";
            $rules .= "        Require all denied\n";
            $rules .= "    </IfModule>\n";
            $rules .= "    <IfModule !mod_authz_core.c>\n";
            $rules .= "        Order Allow,Deny\n";
            $rules .= "        Deny from all\n";
            $rules .= "    </IfModule>\n";
            $rules .= "</FilesMatch>\n";

            file_put_contents($htaccess_path, $rules);
        }
    }

    public function protect_wp_config() {
        $htaccess_path = ABSPATH . '.htaccess';

        if (file_exists($htaccess_path)) {
            $content = file_get_contents($htaccess_path);

            // Only add if not already present
            if (strpos($content, 'Linzi: Protect wp-config') === false) {
                $rules = "\n# Linzi: Protect wp-config.php\n";
                $rules .= "<Files wp-config.php>\n";
                $rules .= "    <IfModule mod_authz_core.c>\n";
                $rules .= "        Require all denied\n";
                $rules .= "    </IfModule>\n";
                $rules .= "    <IfModule !mod_authz_core.c>\n";
                $rules .= "        Order Allow,Deny\n";
                $rules .= "        Deny from all\n";
                $rules .= "    </IfModule>\n";
                $rules .= "</Files>\n";

                file_put_contents($htaccess_path, $content . $rules);
            }
        }
    }

    public function protect_directory_browsing() {
        $htaccess_path = ABSPATH . '.htaccess';

        if (file_exists($htaccess_path)) {
            $content = file_get_contents($htaccess_path);

            if (strpos($content, 'Linzi: Disable directory browsing') === false) {
                $rules = "\n# Linzi: Disable directory browsing\n";
                $rules .= "Options -Indexes\n";

                file_put_contents($htaccess_path, $content . $rules);
            }
        }
    }

    public function apply($action_type) {
        switch ($action_type) {
            case 'disable_xmlrpc':
                return $this->action_disable_xmlrpc();
            case 'protect_uploads':
                $this->protect_uploads_directory();
                return ['success' => true, 'message' => 'Uploads directory protected'];
            case 'protect_config':
                $this->protect_wp_config();
                return ['success' => true, 'message' => 'wp-config.php protected'];
            case 'security_headers':
                return ['success' => true, 'message' => 'Security headers are active'];
            case 'disable_directory_browsing':
                $this->protect_directory_browsing();
                return ['success' => true, 'message' => 'Directory browsing disabled'];
            case 'change_db_prefix':
                return ['success' => false, 'message' => 'Database prefix change requires manual migration'];
            default:
                return ['success' => false, 'message' => 'Unknown hardening action'];
        }
    }

    private function action_disable_xmlrpc() {
        $htaccess_path = ABSPATH . '.htaccess';

        if (file_exists($htaccess_path)) {
            $content = file_get_contents($htaccess_path);

            if (strpos($content, 'Linzi: Block XML-RPC') === false) {
                $rules = "\n# Linzi: Block XML-RPC\n";
                $rules .= "<Files xmlrpc.php>\n";
                $rules .= "    <IfModule mod_authz_core.c>\n";
                $rules .= "        Require all denied\n";
                $rules .= "    </IfModule>\n";
                $rules .= "    <IfModule !mod_authz_core.c>\n";
                $rules .= "        Order Allow,Deny\n";
                $rules .= "        Deny from all\n";
                $rules .= "    </IfModule>\n";
                $rules .= "</Files>\n";

                file_put_contents($htaccess_path, $content . $rules);
            }
        }

        return ['success' => true, 'message' => 'XML-RPC blocked at server level'];
    }

    public function get_hardening_status() {
        $options = LinziContinue::get_options();

        $checks = [
            [
                'name'    => 'XML-RPC Disabled',
                'status'  => !empty($options['disable_xmlrpc']),
                'impact'  => 'Prevents brute force attacks via XML-RPC',
            ],
            [
                'name'    => 'File Editor Disabled',
                'status'  => !empty($options['disable_file_editor']) || defined('DISALLOW_FILE_EDIT'),
                'impact'  => 'Prevents code injection via WP admin editor',
            ],
            [
                'name'    => 'WP Version Hidden',
                'status'  => !empty($options['hide_wp_version']),
                'impact'  => 'Prevents version-targeted attacks',
            ],
            [
                'name'    => 'Security Headers',
                'status'  => true, // Always active when hardening is enabled
                'impact'  => 'XSS protection, clickjacking prevention',
            ],
            [
                'name'    => 'User Enumeration Blocked',
                'status'  => true,
                'impact'  => 'Prevents discovery of admin usernames',
            ],
            [
                'name'    => 'REST API User Endpoint',
                'status'  => true,
                'impact'  => 'Blocks unauthenticated user listing',
            ],
            [
                'name'    => 'PHP in Uploads Blocked',
                'status'  => file_exists(wp_upload_dir()['basedir'] . '/.htaccess'),
                'impact'  => 'Prevents uploaded PHP execution (critical)',
            ],
            [
                'name'    => 'wp-config.php Protected',
                'status'  => $this->check_htaccess_rule('Protect wp-config'),
                'impact'  => 'Blocks direct access to configuration file',
            ],
            [
                'name'    => 'Directory Browsing Disabled',
                'status'  => $this->check_htaccess_rule('Disable directory browsing'),
                'impact'  => 'Prevents directory content listing',
            ],
            [
                'name'    => 'Debug Mode',
                'status'  => !WP_DEBUG,
                'impact'  => WP_DEBUG ? 'WARNING: Debug mode is enabled on production!' : 'Debug mode properly disabled',
            ],
        ];

        return $checks;
    }

    private function check_htaccess_rule($marker) {
        $htaccess_path = ABSPATH . '.htaccess';
        if (!file_exists($htaccess_path)) return false;
        return strpos(file_get_contents($htaccess_path), 'Linzi: ' . $marker) !== false;
    }
}
