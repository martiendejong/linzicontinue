/**
 * Linzi Security - Admin JavaScript
 */
(function ($) {
    'use strict';

    // === Toast Notifications ===
    function showToast(message, type) {
        type = type || 'success';
        var $toast = $('<div class="linzi-toast linzi-toast-' + type + '">' + escapeHtml(message) + '</div>');
        $('body').append($toast);
        setTimeout(function () {
            $toast.fadeOut(300, function () { $(this).remove(); });
        }, 4000);
    }

    // === Fix Single Issue ===
    $(document).on('click', '.linzi-fix-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var action = $btn.data('action');
        var confirmMsg = $btn.data('confirm');

        if (!action) return;

        // Handle approve_mu action separately (goes to different AJAX handler)
        if (action.indexOf('approve_mu:') === 0) {
            var filename = action.split(':').slice(1).join(':');
            if (confirmMsg && !confirm(confirmMsg)) return;

            $btn.prop('disabled', true).css('opacity', 0.6);

            $.ajax({
                url: linziData.ajaxUrl,
                method: 'POST',
                data: {
                    action: 'linzi_approve_mu',
                    nonce: linziData.nonce,
                    filename: filename
                },
                success: function (response) {
                    if (response.success) {
                        showToast('MU-plugin approved');
                        removeIssueCard($btn);
                    } else {
                        showToast('Failed to approve', 'error');
                        $btn.prop('disabled', false).css('opacity', 1);
                    }
                },
                error: function () {
                    showToast('Request failed', 'error');
                    $btn.prop('disabled', false).css('opacity', 1);
                }
            });
            return;
        }

        // Confirm dialog
        if (confirmMsg && !confirm(confirmMsg)) return;

        $btn.prop('disabled', true);
        var origText = $btn.html();
        $btn.html('<span class="dashicons dashicons-update" style="margin-top:4px;animation:rotation 1s infinite linear"></span> Fixing...');

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_fix_issue',
                nonce: linziData.nonce,
                issue_id: action
            },
            success: function (response) {
                if (response.success) {
                    showToast(response.data.message || 'Fixed!');
                    removeIssueCard($btn);
                } else {
                    showToast(response.data.message || 'Fix failed', 'error');
                    $btn.html(origText).prop('disabled', false);
                }
            },
            error: function () {
                showToast('Request failed. Try again.', 'error');
                $btn.html(origText).prop('disabled', false);
            }
        });
    });

    // === Fix All Critical & High ===
    $(document).on('click', '.linzi-fix-all-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);

        if (!confirm('Fix ALL critical and high severity issues?\n\nThis will quarantine malware, enable hardening, block PHP in uploads, and apply safe fixes.\n\nDestructive actions (account deletion, plugin deletion) will be skipped and require manual confirmation.')) {
            return;
        }

        $btn.prop('disabled', true);
        $btn.html('<span class="dashicons dashicons-update" style="margin-top:4px;animation:rotation 1s infinite linear"></span> Fixing all...');

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_fix_all',
                nonce: linziData.nonce
            },
            timeout: 120000,
            success: function (response) {
                if (response.success) {
                    var data = response.data;
                    showToast('Done! Fixed: ' + data.fixed + ', Failed: ' + data.failed + ' of ' + data.total);
                    // Reload page to show updated state
                    setTimeout(function () { location.reload(); }, 1500);
                } else {
                    showToast('Fix all failed', 'error');
                    $btn.prop('disabled', false).html('Fix All Critical & High');
                }
            },
            error: function () {
                showToast('Request failed or timed out', 'error');
                $btn.prop('disabled', false).html('Fix All Critical & High');
            }
        });
    });

    // === Remove issue card with animation ===
    function removeIssueCard($btn) {
        var $card = $btn.closest('.linzi-issue-card');
        if ($card.length) {
            var $group = $card.closest('.linzi-issue-group');
            $card.fadeOut(400, function () {
                $(this).remove();
                // If group is now empty, remove the group
                if ($group.length && $group.find('.linzi-issue-card').length === 0) {
                    $group.fadeOut(300, function () {
                        $(this).remove();
                        // If no groups left, show all clear
                        if ($('.linzi-issue-group').length === 0) {
                            $('#linzi-issues-container').html(
                                '<div class="linzi-section">' +
                                '<div class="linzi-all-clear">' +
                                '<div class="linzi-all-clear-icon">&#x2705;</div>' +
                                '<h2>All Clear</h2>' +
                                '<p>All issues have been resolved. Your site is protected.</p>' +
                                '</div></div>'
                            );
                            // Hide the Fix All button
                            $('.linzi-fix-all-btn').fadeOut();
                            // Reload to update score
                            setTimeout(function () { location.reload(); }, 2000);
                        }
                    });
                } else if ($group.length) {
                    // Update the issue count in group header
                    var remaining = $group.find('.linzi-issue-card').length;
                    $group.find('.linzi-issue-count').text(remaining + (remaining === 1 ? ' issue' : ' issues'));
                }
            });
        } else {
            // Fallback: remove table row (for firewall/mu pages)
            var $row = $btn.closest('tr');
            if ($row.length) {
                $row.fadeOut(400, function () { $(this).remove(); });
            } else {
                // Last resort: reload
                setTimeout(function () { location.reload(); }, 500);
            }
        }

        // Update topbar counts
        updateTopbarCounts();
    }

    // === Update topbar severity counts after a fix ===
    function updateTopbarCounts() {
        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_get_issues',
                nonce: linziData.nonce
            },
            success: function (response) {
                if (response.success && response.data.summary) {
                    var s = response.data.summary;
                    $('.linzi-topbar-stat-num.linzi-color-critical').text(s.critical);
                    $('.linzi-topbar-stat-num.linzi-color-high').text(s.high);
                    $('.linzi-topbar-stat-num.linzi-color-medium').text(s.medium);
                    $('.linzi-topbar-stat-num.linzi-color-low').text(s.low);
                }
            }
        });
    }

    // === Scan Controls ===
    $(document).on('click', '.linzi-scan-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);

        // Don't trigger scan if this is a fix button that happens to have scan class
        if ($btn.data('action')) return;

        var scanType = $btn.data('type') || 'standard';

        // Disable all scan buttons
        $('.linzi-scan-btn').prop('disabled', true).css('opacity', 0.5);

        // Show progress
        $('#linzi-scan-progress').show();
        $('#linzi-scan-results').hide();

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_run_scan',
                nonce: linziData.nonce,
                scan_type: scanType
            },
            timeout: 300000, // 5 minute timeout for deep scans
            success: function (response) {
                $('#linzi-scan-progress').hide();
                $('.linzi-scan-btn').prop('disabled', false).css('opacity', 1);

                if (response.success) {
                    var data = response.data;
                    var html = '<div class="linzi-section">';
                    html += '<h2>Scan Complete</h2>';
                    html += '<p>Files scanned: <strong>' + data.files_scanned.toLocaleString() + '</strong> | ';
                    html += 'Threats found: <strong>' + data.threat_count + '</strong> | ';
                    html += 'Completed: <strong>' + data.completed_at + '</strong></p>';

                    if (data.threats && data.threats.length > 0) {
                        html += '<table class="widefat linzi-table">';
                        html += '<thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Description</th><th>Actions</th></tr></thead>';
                        html += '<tbody>';

                        data.threats.forEach(function (threat) {
                            html += '<tr class="linzi-threat-' + threat.severity + '">';
                            html += '<td><span class="linzi-severity linzi-severity-' + threat.severity + '">' + threat.severity.toUpperCase() + '</span></td>';
                            html += '<td>' + escapeHtml(threat.threat_type) + '</td>';
                            html += '<td><code>' + escapeHtml(threat.file_path.split(/[/\\]/).pop()) + '</code></td>';
                            html += '<td>' + escapeHtml(threat.description || '').substring(0, 100) + '</td>';
                            html += '<td><button class="button button-primary linzi-quarantine-btn" data-file="' + escapeHtml(threat.file_path) + '">Quarantine</button></td>';
                            html += '</tr>';
                        });

                        html += '</tbody></table>';
                    } else {
                        html += '<div class="linzi-success-message">';
                        html += '<span class="dashicons dashicons-yes-alt" style="font-size:40px;color:#46b450;"></span>';
                        html += '<h3>No threats detected!</h3>';
                        html += '<p>Your site appears clean.</p>';
                        html += '</div>';
                    }

                    html += '</div>';
                    $('#linzi-scan-results').html(html).show();

                    // Reload page after 2 seconds to update stats/threat center
                    setTimeout(function () {
                        location.reload();
                    }, 2000);
                }
            },
            error: function (xhr, status, error) {
                $('#linzi-scan-progress').hide();
                $('.linzi-scan-btn').prop('disabled', false).css('opacity', 1);
                alert('Scan failed: ' + error + '. The scan may have timed out for very large sites.');
            }
        });
    });

    // === Quarantine (from scan results table) ===
    $(document).on('click', '.linzi-quarantine-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var file = $btn.data('file');

        if (!confirm('Quarantine this file?\n\n' + file + '\n\nThe file will be moved to a safe location and can be restored later.')) {
            return;
        }

        $btn.prop('disabled', true).text('Quarantining...');

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_quarantine',
                nonce: linziData.nonce,
                file: file
            },
            success: function (response) {
                if (response.success) {
                    showToast('File quarantined');
                    $btn.closest('tr').fadeOut(400, function () {
                        $(this).remove();
                    });
                } else {
                    showToast('Failed to quarantine: ' + (response.error || 'Unknown error'), 'error');
                    $btn.prop('disabled', false).text('Quarantine');
                }
            },
            error: function () {
                showToast('Request failed', 'error');
                $btn.prop('disabled', false).text('Quarantine');
            }
        });
    });

    // === Dismiss Threat ===
    $(document).on('click', '.linzi-dismiss-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var threatId = $btn.data('id');

        if (!confirm('Dismiss this threat? It will be marked as reviewed and removed from the active list.')) {
            return;
        }

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_dismiss_threat',
                nonce: linziData.nonce,
                threat_id: threatId
            },
            success: function (response) {
                if (response.success) {
                    $btn.closest('tr').fadeOut(400, function () {
                        $(this).remove();
                    });
                }
            }
        });
    });

    // === Approve MU-Plugin (standalone button on MU page) ===
    $(document).on('click', '.linzi-approve-mu-btn', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filename = $btn.data('filename');

        if (!confirm('Approve this mu-plugin as legitimate?\n\n' + filename + '\n\nOnly approve if you are sure this is a trusted file.')) {
            return;
        }

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_approve_mu',
                nonce: linziData.nonce,
                filename: filename
            },
            success: function (response) {
                if (response.success) {
                    showToast('MU-plugin approved');
                    location.reload();
                }
            }
        });
    });

    // === Activity Log Loading ===
    function loadActivityLog(page) {
        page = page || 1;
        var $container = $('#linzi-activity-container');

        $container.html('<div class="linzi-loading">Loading activity log...</div>');

        $.ajax({
            url: linziData.ajaxUrl,
            method: 'POST',
            data: {
                action: 'linzi_get_activity',
                nonce: linziData.nonce,
                page: page
            },
            success: function (response) {
                if (response.success && response.data) {
                    var data = response.data;
                    var html = '';

                    if (data.logs && data.logs.length > 0) {
                        html += '<table class="widefat linzi-table linzi-activity-table">';
                        html += '<thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>User</th><th>IP</th><th>Description</th></tr></thead>';
                        html += '<tbody>';

                        data.logs.forEach(function (log) {
                            html += '<tr class="severity-' + log.severity + '">';
                            html += '<td>' + escapeHtml(log.created_at) + '</td>';
                            html += '<td><code>' + escapeHtml(log.event_type) + '</code></td>';
                            html += '<td><span class="linzi-severity linzi-severity-' + mapSeverity(log.severity) + '">' + escapeHtml(log.severity).toUpperCase() + '</span></td>';
                            html += '<td>' + escapeHtml(log.user_login || '-') + '</td>';
                            html += '<td><code>' + escapeHtml(log.ip_address || '-') + '</code></td>';
                            html += '<td>' + escapeHtml(log.description) + '</td>';
                            html += '</tr>';
                        });

                        html += '</tbody></table>';

                        // Pagination
                        if (data.pages > 1) {
                            html += '<div class="linzi-pagination">';
                            for (var i = 1; i <= Math.min(data.pages, 10); i++) {
                                var cls = i === data.page ? 'page-numbers current' : 'page-numbers';
                                html += '<a href="#" class="' + cls + '" data-page="' + i + '">' + i + '</a>';
                            }
                            html += '</div>';
                        }
                    } else {
                        html += '<div class="linzi-success-message"><p>No activity logged yet.</p></div>';
                    }

                    $container.html(html);
                }
            },
            error: function () {
                $container.html('<div class="notice notice-error"><p>Failed to load activity log.</p></div>');
            }
        });
    }

    // Pagination click
    $(document).on('click', '.linzi-pagination .page-numbers', function (e) {
        e.preventDefault();
        loadActivityLog($(this).data('page'));
    });

    // Auto-load activity log on activity page
    if ($('#linzi-activity-container').length) {
        loadActivityLog(1);
    }

    // === Utility Functions ===
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function mapSeverity(severity) {
        var map = {
            'critical': 'critical',
            'warning': 'high',
            'info': 'medium',
            'debug': 'low'
        };
        return map[severity] || 'medium';
    }

    // === CSS Animation for spinner ===
    if (!document.getElementById('linzi-spinner-style')) {
        var style = document.createElement('style');
        style.id = 'linzi-spinner-style';
        style.textContent = '@keyframes rotation { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    }

})(jQuery);
