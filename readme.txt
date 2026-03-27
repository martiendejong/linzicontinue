=== Linzi Security ===
Contributors: promotiemeester
Tags: security, firewall, malware, scanner, mu-plugins, login protection, hardening
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced WordPress security suite with firewall, malware scanner, mu-plugins guardian, login protection, file integrity monitoring, and real-time threat dashboard. Built from real-world breach forensics.

== Description ==

Linzi Security is a comprehensive WordPress security plugin built from real-world breach investigation experience. Unlike other security plugins, Linzi specifically targets the actual attack vectors used by hackers, including the often-overlooked mu-plugins persistence mechanism.

= Key Features =

* **Web Application Firewall (WAF)** - Blocks SQL injection, XSS, path traversal, remote code execution, and other OWASP Top 10 attacks in real-time
* **Malware Scanner** - 30+ signatures based on real-world malware samples, scans plugins, themes, uploads, mu-plugins, and core files
* **MU-Plugins Guardian** - The #1 persistence mechanism for WordPress malware, monitored every 5 minutes with deep code analysis
* **Login Protection** - Brute force prevention, account lockout, new IP alerts for admin accounts, login error obfuscation
* **File Integrity Monitoring** - Hourly checks for unauthorized file modifications, new files, and deletions
* **Security Hardening** - XML-RPC blocking, file editor disabling, version hiding, security headers, PHP execution blocking in uploads, wp-config protection
* **Activity Logging** - Complete audit trail of admin actions, login attempts, plugin changes, role modifications, and critical setting changes
* **Real-time Dashboard** - Security score, threat overview, attack statistics, and quick actions
* **Email Alerts** - Instant notifications for critical threats, brute force attacks, new admin IP addresses, and file integrity changes
* **Quarantine System** - Safely isolate suspicious files with metadata preservation and restore capability

= What Makes Linzi Different =

1. **Built from real breach forensics** - Not theoretical threats, but actual attack patterns observed in production
2. **MU-Plugins focus** - Other plugins ignore the #1 persistence mechanism. Linzi monitors it every 5 minutes
3. **Fake plugin detection** - Identifies plugins that look legitimate but contain backdoors
4. **Polymorphic JavaScript detection** - Catches malware that changes variable names on each page load
5. **Rogue admin account detection** - Finds administrator accounts created by attackers
6. **Completely free** - No paid tiers, no feature limitations, no upselling

= Security Checks =

* SQL injection prevention
* Cross-site scripting (XSS) blocking
* Path traversal blocking
* Remote code execution prevention
* File inclusion attack prevention
* Sensitive file access blocking
* Bad bot detection
* XML-RPC attack prevention
* Rate limiting
* User enumeration prevention
* PHP execution in uploads directory
* Directory browsing prevention
* WordPress version exposure

== Installation ==

1. Upload the `linzicontinue` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to Linzi in the admin menu to configure settings
4. Run your first scan

== Frequently Asked Questions ==

= Is Linzi really free? =

Yes. All features are free with no premium tier.

= Will it slow down my site? =

The firewall runs efficiently on every request. Scans run in the background (or on schedule). MU-plugin checks are lightweight (5-minute intervals).

= Can I use it alongside other security plugins? =

Yes, but we recommend disabling overlapping features to avoid conflicts (e.g., don't run two firewalls simultaneously).

= What happens when a file is quarantined? =

The file is moved to a protected directory (wp-content/linzi-quarantine/) with metadata preserved. It can be restored at any time.

== Changelog ==

= 1.0.0 =
* Initial release
* Web Application Firewall with 10 rule categories
* Malware Scanner with 30+ signatures
* MU-Plugins Guardian with 5-minute monitoring
* Login Protection with brute force prevention
* File Integrity Monitoring
* Security Hardening (9 checks)
* Activity Logging (15+ event types)
* Admin Dashboard with security score
* Email alerting system
* REST API for programmatic access
* Quarantine system with restore capability
