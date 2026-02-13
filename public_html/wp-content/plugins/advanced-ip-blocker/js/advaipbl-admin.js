jQuery(document).ready(function ($) {

    // Objeto global con todos los datos y textos pasados desde PHP.
    const adminData = window.advaipbl_admin_data || {};

    // ========================================================================
    // FUNCIONES DE UI REUTILIZABLES (MODAL Y NOTIFICACIONES)
    // ========================================================================

    function showAdminNotice(message, type = 'error') {
        if (typeof message === 'undefined' || message === '') return;
        const container = $('#advaipbl-notices-container');
        if (!container.length) return;
        const noticeHtml = `<div class="notice notice-${type} is-dismissible"><p>${message}</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>`;
        container.append(noticeHtml);
        container.find('.notice-dismiss').last().on('click', function (e) { e.preventDefault(); $(this).closest('.notice').fadeOut('slow', function () { $(this).remove(); }); });
    }

    function showConfirmModal(options) {
        const modal = $('#advaipbl-general-confirm-modal');
        modal.find('.advaipbl-modal-title').html(options.title || 'Are you sure?');
        modal.find('.advaipbl-modal-body').html(options.message || '');
        modal.find('#advaipbl-confirm-action-btn').text(options.confirmText || 'Confirm');

        modal.fadeIn('fast');

        const confirmBtn = modal.find('#advaipbl-confirm-action-btn');
        const cancelBtn = modal.find('.advaipbl-modal-cancel');

        confirmBtn.off('click');
        cancelBtn.off('click');

        confirmBtn.on('click', function () {
            if (typeof options.onConfirm === 'function') { options.onConfirm(); }
            modal.fadeOut('fast');
        });

        cancelBtn.on('click', function () {
            modal.fadeOut('fast');
        });
    }

    /**
     * Maneja la lógica de las acciones masivas (Bulk Actions) de forma robusta.
     */
    function initBulkActions() {
        const form = $('#advaipbl-blocked-ips-form');
        if (!form.length) return;

        const topSelector = form.find('#bulk-action-selector-top');
        const bottomSelector = form.find('#bulk-action-selector-bottom');

        topSelector.on('change', function () {
            bottomSelector.val($(this).val());
        });

        bottomSelector.on('change', function () {
            topSelector.val($(this).val());
        });

        form.find('#cb-select-all-1, #cb-select-all-2').on('click', function () {
            const isChecked = $(this).prop('checked');
            form.find('#the-list input[type="checkbox"][name="ips_to_process[]"]').prop('checked', isChecked);
        });

        form.find('input[type="submit"].action').on('click', function (e) {
            e.preventDefault();

            const isTopButton = $(this).attr('id') === 'doaction';
            const actionSelector = isTopButton ? $('#bulk-action-selector-top') : $('#bulk-action-selector-bottom');
            const action = actionSelector.val();

            if (action === '-1') {
                const alertText = (adminData.text && adminData.text.alert_no_action) ? adminData.text.alert_no_action : 'Please select a bulk action.';
                alert(alertText);
                return;
            }

            if (action === 'unblock_all') {
                showConfirmModal({
                    title: 'Confirm Mass Unblock',
                    message: 'Are you sure you want to unblock ALL IPs from ALL blocklists? This action cannot be undone.',
                    confirmText: 'Yes, Unblock All IPs',
                    onConfirm: function () {
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            } else if (action === 'unblock') {
                const checkedItems = form.find('#the-list input[type="checkbox"][name="ips_to_process[]"]:checked');
                if (checkedItems.length === 0) {
                    const alertItemsText = (adminData.text && adminData.text.alert_no_items) ? adminData.text.alert_no_items : 'Please select at least one item to apply the action.';
                    alert(alertItemsText);
                    return;
                }
                showConfirmModal({
                    title: (adminData.text && adminData.text.confirm_bulk_action_title) ? adminData.text.confirm_bulk_action_title : 'Confirm Bulk Action',
                    message: ((adminData.text && adminData.text.confirm_bulk_unblock_message) ? adminData.text.confirm_bulk_unblock_message : 'Are you sure you want to unblock the selected %d entries?').replace('%d', checkedItems.length),
                    confirmText: (adminData.text && adminData.text.confirm_bulk_unblock_button) ? adminData.text.confirm_bulk_unblock_button : 'Yes, Unblock Selected',
                    onConfirm: function () {
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            }
        });
    }

    /**
 * Maneja la lógica de las acciones masivas para la tabla de la Whitelist.
 */
    function initWhitelistBulkActions() {
        const form = $('#advaipbl-whitelist-form');
        if (!form.length) return;

        // Lógica para los checkboxes "seleccionar todo"
        form.find('#cb-select-all-1').on('click', function () {
            const isChecked = $(this).prop('checked');
            form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]').prop('checked', isChecked);
        });

        // Lógica para los botones "Apply"
        form.find('input[type="submit"].action').on('click', function (e) {
            e.preventDefault();

            const isTopButton = $(this).attr('id') === 'doaction';
            const actionSelector = isTopButton ? $('#bulk-action-selector-top') : $('#bulk-action-selector-bottom');
            const action = actionSelector.val();

            if (action === '-1') {
                const alertText = (adminData.text && adminData.text.alert_no_action) ? adminData.text.alert_no_action : 'Please select a bulk action.';
                alert(alertText);
                return;
            }

            const checkedItems = form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]:checked');
            if (checkedItems.length === 0) {
                const alertItemsText = (adminData.text && adminData.text.alert_no_items) ? adminData.text.alert_no_items : 'Please select at least one item to apply the action.';
                alert(alertItemsText);
                return;
            }

            if (action === 'remove') {
                showConfirmModal({
                    title: 'Confirm Removal',
                    message: ((adminData.text && adminData.text.confirm_bulk_whitelist_remove_message) ? adminData.text.confirm_bulk_whitelist_remove_message : 'Are you sure you want to remove the selected %d entries from the whitelist?').replace('%d', checkedItems.length),
                    confirmText: 'Yes, Remove Selected',
                    onConfirm: function () {
                        // Asegurarse de que ambos selectores tienen el valor correcto antes de enviar
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            }
        });
    }

    /**
     * Maneja el cambio de los filtros de la tabla de IPs Bloqueadas para recargar la página.
     */
    function initBlockedIpsFilters() {
        // Seleccionamos los filtros que NO están dentro del formulario de acciones masivas
        $('#filter-by-type, .advaipbl-per-page-selector').not('#advaipbl-blocked-ips-form .advaipbl-per-page-selector').on('change', function () {
            let currentUrl = window.location.href.split('?')[0];
            let params = new URLSearchParams(window.location.search);
            params.set('filter_type', $('#filter-by-type').val());
            params.set('advaipbl_per_page', $('.advaipbl-per-page-selector').val());
            params.set('paged', 1);
            window.location.href = currentUrl + '?' + params.toString();
        });
    }

    // ========================================================================
    // LÓGICA ESPECÍFICA DE LAS PESTAÑAS
    // ========================================================================

    /**
     * Maneja la lógica para abrir y cerrar el modal del mapa.
     */
    function initMapViewModal() {
        $(document).on('click', '.advaipbl-btn-map', function (e) {
            e.preventDefault();
            const lat = $(this).data('lat');
            const lon = $(this).data('lon');
            if (!lat || !lon) return;
            const mapUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.01},${lat - 0.01},${lon + 0.01},${lat + 0.01}&layer=mapnik&marker=${lat},${lon}`;
            $('#mapModalFrame').attr('src', mapUrl);
            $('#mapModal').css('display', 'flex');
        });

        $('#closeModalBtn').on('click', function () {
            $('#mapModal').fadeOut('fast', function () {
                $('#mapModalFrame').attr('src', '');
            });
        });
    }

    /**
     * Adjunta las advertencias de seguridad a todos los selectores de países (Geoblock y Geo-Challenge).
     */
    function attachGeoblockWarning() {
        if (typeof adminData.geoblock === 'undefined') return;

        // Iteramos sobre cada selector de país que tengamos en la página
        $('.advaipbl-country-select').each(function () {
            const $selector = $(this);
            const selectorId = $selector.attr('id');
            const isChallengeSelector = selectorId === 'advaipbl_geo_challenge_countries';

            const data = adminData.geoblock;
            const server = data.server || {};
            const admin = data.admin || {};
            const texts = adminData.text || {};

            const countryList = isChallengeSelector ? (data.challenged_countries || []) : (data.blocked_countries || []);

            const warningContainer = $('<div class="advaipbl-geoblock-warnings"></div>');
            $selector.parent().append(warningContainer);

            const checkAndDisplayWarnings = function () {
                const selectedCountries = $selector.val() || [];
                warningContainer.empty().hide();

                const serverCountrySelected = server.country_code && selectedCountries.includes(server.country_code);
                const isAdminCountrySelected = admin.country_code && selectedCountries.includes(admin.country_code);

                const createButtonHtml = (ip, detail) => ` <button class="button button-secondary advaipbl-add-whitelist-ajax" data-ip="${ip}" data-detail="${detail}">${texts.add_to_whitelist_btn}</button>`;

                let serverMessageHtml = '';
                if (serverCountrySelected && server.ip) {
                    const serverText = server.is_whitelisted ? texts.server_whitelisted : texts.server_not_whitelisted;
                    const serverType = server.is_whitelisted ? 'info' : 'error';
                    const serverButton = server.is_whitelisted ? '' : createButtonHtml(server.ip, 'Server IP (auto-added via warning)');
                    const formattedText = serverText.replace('%1$s', `<strong>${server.country_name || server.country_code}</strong>`).replace('%2$s', `<code>${server.ip}</code>`);
                    serverMessageHtml = `<div class="advaipbl-notice advaipbl-notice-${serverType}"><p>${formattedText}${serverButton}</p></div>`;
                }

                let adminMessageHtml = '';
                if (isAdminCountrySelected && admin.ip && admin.ip !== server.ip) {
                    const adminText = admin.is_whitelisted ? texts.admin_whitelisted : texts.admin_not_whitelisted;
                    const adminType = admin.is_whitelisted ? 'info' : 'warning';
                    const adminButton = admin.is_whitelisted ? '' : createButtonHtml(admin.ip, 'Admin IP (auto-added via warning)');
                    const formattedText = adminText.replace('%1$s', `<code>${admin.ip}</code>`).replace('%2$s', `<strong>${admin.country_name || admin.country_code}</strong>`);
                    adminMessageHtml = `<div class="advaipbl-notice advaipbl-notice-${adminType}"><p>${formattedText}${adminButton}</p></div>`;
                }

                if (serverMessageHtml || adminMessageHtml) {
                    warningContainer.append(serverMessageHtml).append(adminMessageHtml).slideDown('fast');
                }
            };

            $selector.on('change', checkAndDisplayWarnings);
            checkAndDisplayWarnings(); // Ejecutar al cargar la página
        });
    }

    function attachWhitelistRemoveWarning() { $('body').on('click', '.advaipbl-remove-whitelist-button', function (e) { e.preventDefault(); const form = $(this).closest('form'); if (typeof adminData.geoblock === 'undefined') { form.get(0).submit(); return; } const ipToRemove = $(this).data('ip-to-remove'); const data = adminData.geoblock; const server = data.server || {}; const admin = data.admin || {}; const blockedCountries = data.blocked_countries || []; const texts = adminData.text || {}; let warningMessage = ''; if (server.ip === ipToRemove && server.country_code && blockedCountries.includes(server.country_code)) { warningMessage += texts.remove_server_ip_warning.replace('%1$s', `<strong>${server.ip}</strong>`).replace('%2$s', `<strong>${server.country_name}</strong>`) + '<br><br>'; } if (admin.ip === ipToRemove && admin.country_code && blockedCountries.includes(admin.country_code)) { warningMessage += texts.remove_admin_ip_warning.replace('%1$s', `<strong>${admin.ip}</strong>`).replace('%2$s', `<strong>${admin.country_name || admin.country_code}</strong>`) + '<br><br>'; } if (warningMessage) { warningMessage += texts.confirm_removal; showConfirmModal({ title: 'Confirmation Required', message: warningMessage, confirmText: 'Yes, Proceed', onConfirm: function () { form.get(0).submit(); } }); } else { form.get(0).submit(); } }); }
    function initWhitelistAjaxButton() { $('body').on('click', '.advaipbl-add-whitelist-ajax', function (e) { e.preventDefault(); const $button = $(this); const ip = $button.data('ip'); const detail = $button.data('detail'); const originalText = $button.html(); const texts = adminData.text || {}; $button.text(texts.adding_to_whitelist).prop('disabled', true); $.post(ajaxurl, { action: 'advaipbl_add_ip_to_whitelist', nonce: adminData.nonces.add_whitelist, ip: ip, detail: detail }).done(function (response) { if (response.success) { const successHtml = `<span class="advaipbl-status-icon success" title="${response.data.message}">✔ ${texts.added_to_whitelist}</span>`; const $notice = $button.closest('.advaipbl-notice'); $button.replaceWith(successHtml); if ($notice.length) { $notice.removeClass('advaipbl-notice-error advaipbl-notice-warning').addClass('advaipbl-notice-info'); } } else { $button.html(originalText).prop('disabled', false); showAdminNotice('Error: ' + response.data.message, 'error'); } }).fail(function () { $button.html(originalText).prop('disabled', false); showAdminNotice(texts.ajax_error, 'error'); }); }); }
    function initMobileNav() { $('#advaipbl-nav-select').on('change', function () { const newUrl = $(this).val(); if (newUrl) { window.location.href = newUrl; } }); }
    function toggleRecaptchaV3Options() { const version = $('#advaipbl_recaptcha_version').val(); $('#advaipbl-recaptcha-v3-options-row').toggle(version === 'v3'); }
    function initConnectionTest() { $('#advaipbl-test-connection-btn').on('click', function (e) { e.preventDefault(); const $button = $(this); const $resultSpan = $('#advaipbl-test-connection-result'); const originalText = $button.text(); $button.text('Testing...').prop('disabled', true); $resultSpan.text('').removeClass('success error'); $.post(ajaxurl, { action: 'advaipbl_test_outbound_connection', nonce: adminData.nonces.test_connection }).done(function (response) { if (response.success) { $resultSpan.text(response.data.message).css('color', 'green'); } else { $resultSpan.text(response.data.message).css('color', '#d63638'); } }).fail(function () { showAdminNotice(adminData.text.ajax_error, 'error'); }).always(function () { $button.text(originalText).prop('disabled', false); }); }); }
    function initConfirmActions() { $('body').on('click', '.advaipbl-confirm-action', function (e) { e.preventDefault(); const $button = $(this); const form = $button.closest('form'); const options = { title: $button.data('confirm-title') || 'Confirmation Required', message: $button.data('confirm-message') || 'Are you sure you want to proceed?', confirmText: $button.data('confirm-button') || 'Confirm', onConfirm: function () { form.get(0).submit(); } }; showConfirmModal(options); }); }
    //function initGeolocationProviderLogic() { const geoProviderSelector = $('#advaipbl_geolocation_provider_select'); if (!geoProviderSelector.length) { return; } const toggleApiKeyFields = function() { const selectedProvider = geoProviderSelector.val(); $('.api-key-field').closest('tr').hide(); const selector = `input[data-provider="${selectedProvider}"]`; $(selector).closest('tr').show(); }; toggleApiKeyFields(); geoProviderSelector.on('change', toggleApiKeyFields); }
    /**
     * Maneja la exportación de ajustes vía AJAX y descarga en el cliente.
     */
    function initExportLogic() {
        $('#advaipbl-export-template, #advaipbl-export-full').on('click', function (e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            $button.text('Exporting...').prop('disabled', true);
            const exportType = $button.data('export-type');

            $.post(ajaxurl, {
                action: 'advaipbl_export_settings_ajax',
                nonce: adminData.nonces.export,
                export_type: exportType
            })
                .done(function (response) {
                    if (response.success) {
                        const data = response.data;
                        const blob = new Blob([JSON.stringify(data.settings, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        const date = new Date().toISOString().slice(0, 10);
                        a.href = url;
                        a.download = `advaipbl-settings-${data.type}-${date}.json`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    } else {
                        showAdminNotice('Export failed: ' + response.data.message, 'error');
                    }
                })
                .fail(function () {
                    showAdminNotice(adminData.text.ajax_error, 'error');
                })
                .always(function () {
                    $button.text(originalText).prop('disabled', false);
                });
        });
    }

    /**
* Maneja los clics en el aviso de consentimiento de telemetría.
*/
    function initTelemetryNotice() {
        $(document).on('click', '#advaipbl-allow-telemetry, #advaipbl-dismiss-telemetry-notice', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $notice = $button.closest('.advaipbl-telemetry-notice');
            const action = $button.attr('id') === 'advaipbl-allow-telemetry' ? 'allow' : 'dismiss';

            $notice.css('opacity', '0.5');

            $.post(ajaxurl, {
                action: 'advaipbl_handle_telemetry_notice',
                nonce: adminData.nonces.telemetry,
                telemetry_action: action
            })
                .done(function (response) {
                    if (response.success) {
                        $notice.fadeOut('slow', function () { $(this).remove(); });
                        if (action === 'allow') {
                            const $checkbox = $('input[name="advaipbl_settings[allow_telemetry]"]');
                            if ($checkbox.length) {
                                $checkbox.prop('checked', true);
                            }
                        }
                    }
                });
        });
    }

    /**
* Maneja la lógica de las acciones masivas para la tabla de la Whitelist.
*/
    function initWhitelistBulkActions() {
        const form = $('#advaipbl-whitelist-form');
        if (!form.length) return;

        form.find('#cb-select-all-1').on('click', function () {
            const isChecked = $(this).prop('checked');
            form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]').prop('checked', isChecked);
        });

        form.find('input[type="submit"].action').on('click', function (e) {
            e.preventDefault();

            const isTopButton = $(this).attr('id') === 'doaction';
            const actionSelector = isTopButton ? form.find('#bulk-action-selector-top') : form.find('#bulk-action-selector-bottom');
            const action = actionSelector.val();

            if (action === '-1') {
                alert(adminData.text.alert_no_action || 'Please select a bulk action.');
                return;
            }

            const checkedItems = form.find('#the-list input[type="checkbox"][name="entries_to_process[]"]:checked');
            if (checkedItems.length === 0) {
                alert(adminData.text.alert_no_items || 'Please select at least one item to apply the action.');
                return;
            }

            if (action === 'remove') {
                showConfirmModal({
                    title: 'Confirm Removal',
                    message: (adminData.text.confirm_bulk_whitelist_remove_message || 'Are you sure you want to remove the selected %d entries from the whitelist?').replace('%d', checkedItems.length),
                    confirmText: 'Yes, Remove Selected',
                    onConfirm: function () {
                        form.find('select[name="bulk_action"], select[name="bulk_action2"]').val(action);
                        form.submit();
                    }
                });
            }
        });
    }

    /**
 * Maneja las acciones en la tabla de IP Trust Log.
 */
    function initIpTrustLogActions() {
        const table = $('#the-list');
        if (!table.length) return;

        // Acción para Resetear Puntuación
        table.on('click', '.advaipbl-reset-score', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const ip = $row.data('ip');

            showConfirmModal({
                title: 'Reset Score?',
                message: `Are you sure you want to reset the threat score for <strong>${ip}</strong> to 0? This action will unblock the IP and remove it from this list.`,
                confirmText: 'Yes, Reset Score',
                onConfirm: function () {
                    $row.css('opacity', '0.5');
                    $.post(ajaxurl, {
                        action: 'advaipbl_reset_threat_score',
                        nonce: adminData.nonces.reset_score,
                        ip: ip
                    }).done(function (response) {
                        if (response.success) {
                            $row.fadeOut('slow', function () { $(this).remove(); });
                        } else {
                            showAdminNotice(response.data.message, 'error');
                            $row.css('opacity', '1');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        $row.css('opacity', '1');
                    });
                }
            });
        });

        // Acción para Ver Historial
        const modal = $('#advaipbl-score-history-modal');
        table.on('click', '.advaipbl-view-score-history', function (e) {
            e.preventDefault();
            const $button = $(this);
            const ip = $button.closest('tr').data('ip');

            modal.find('.modal-ip-placeholder').text(ip);
            modal.find('.history-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, {
                action: 'advaipbl_get_score_history',
                nonce: adminData.nonces.get_history,
                ip: ip
            }).done(function (response) {
                if (response.success && response.data.history) {
                    let historyHtml = '<table class="widefat"><thead><tr><th>Date/Time</th><th>Event</th><th>Points</th><th>Details</th></tr></thead><tbody>';
                    if (response.data.history.length === 0) {
                        historyHtml += '<tr><td colspan="4">No history found.</td></tr>';
                    } else {
                        response.data.history.forEach(function (ev) {
                            const date = new Date(ev.ts * 1000).toLocaleString();

                            let detailsText = '-';
                            if (ev.details) {
                                // Usamos plantillas de texto para escapar HTML y evitar XSS
                                const escapeHtml = (text) => {
                                    if (!text) return 'N/A';
                                    const div = document.createElement('div');
                                    div.textContent = text;
                                    return div.innerHTML;
                                };

                                const uri = escapeHtml(ev.details.uri || ev.details.url);

                                switch (ev.event) {
                                    case 'waf':
                                        detailsText = `Rule: <strong>${escapeHtml(ev.details.rule)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'user_agent':
                                        detailsText = `UA: <strong>${escapeHtml(ev.details.user_agent)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'asn':
                                        const source = escapeHtml(ev.details.source);
                                        const name = escapeHtml(ev.details.asn_name);
                                        detailsText = `ASN: <strong>${escapeHtml(ev.details.asn_number)} (${name})</strong> - ${source}<br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'login':
                                        detailsText = `User: <strong>${escapeHtml(ev.details.username)}</strong>`;
                                        break;
                                    case 'impersonation':
                                        detailsText = `Impersonated UA: <strong>${escapeHtml(ev.details.impersonated_user_agent)}</strong><br><small>URI: ${uri}</small>`;
                                        break;
                                    case 'honeypot':
                                    case '404':
                                    case '403':
                                        detailsText = `URI: ${uri}`;
                                        break;
                                    default:
                                        detailsText = uri !== 'N/A' ? `URI: ${uri}` : '-';
                                }
                            }

                            historyHtml += `<tr><td>${date}</td><td>${ev.event}</td><td>+${ev.points}</td><td>${detailsText}</td></tr>`;
                        });
                    }
                    historyHtml += '</tbody></table>';
                    modal.find('.history-content').html(historyHtml);
                } else {
                    modal.find('.history-content').html('<p>Error retrieving history.</p>');
                }
            }).fail(function () {
                modal.find('.history-content').html('<p>AJAX error.</p>');
            }).always(function () {
                modal.find('.advaipbl-loader-wrapper').hide();
                modal.find('.history-content').show();
            });
        });

        modal.find('.advaipbl-modal-cancel').on('click', function () {
            modal.fadeOut('fast');
        });
    }

    /**
    * Maneja la acción de eliminar firmas maliciosas.
    */
    function initBlockedSignaturesActions() {
        $('body').on('click', '.advaipbl-delete-signature', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const hash = $row.data('hash');
            const shortHash = hash.substring(0, 12) + '...';

            showConfirmModal({
                title: 'Delete Signature?',
                message: `Are you sure you want to delete the signature <strong>${shortHash}</strong>? This will immediately stop challenging visitors with this fingerprint.`,
                confirmText: 'Yes, Delete Signature',
                onConfirm: function () {
                    $row.css('opacity', '0.5');
                    $.post(ajaxurl, {
                        action: 'advaipbl_delete_signature',
                        nonce: adminData.nonces.delete_signature,
                        hash: hash
                    }).done(function (response) {
                        if (response.success) {
                            $row.fadeOut('slow', function () { $(this).remove(); });
                        } else {
                            // Comprobamos si el mensaje de error existe antes de mostrarlo.
                            const errorMessage = (response.data && response.data.message) ? response.data.message : 'An unknown error occurred.';
                            showAdminNotice(errorMessage, 'error');
                            $row.css('opacity', '1');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        $row.css('opacity', '1');
                    });
                }
            });
        });

        const modal = $('#advaipbl-signature-details-modal');
        $('body').on('click', '.advaipbl-view-signature-details', function (e) {
            e.preventDefault();
            const hash = $(this).closest('tr').data('hash');
            const shortHash = hash.substring(0, 12) + '...';

            modal.find('.modal-hash-placeholder').text(shortHash);
            modal.find('.details-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, {
                action: 'advaipbl_get_signature_details',
                nonce: adminData.nonces.get_signature_details,
                hash: hash
            }).done(function (response) {
                if (response.success && response.data.details) {
                    const details = response.data.details;
                    let detailsHtml = '<h4>Signature Components:</h4><ul class="signature-components">';
                    detailsHtml += `<li><strong>User-Agent:</strong> <code>${details.sample_user_agent || 'N/A'}</code></li>`;

                    if (details.sample_headers) {
                        for (const [key, value] of Object.entries(details.sample_headers)) {
                            detailsHtml += `<li><strong>${key}:</strong> <code>${value}</code></li>`;
                        }
                    }
                    detailsHtml += '</ul>';

                    detailsHtml += '<h4>Attack Evidence (last 15 entries):</h4><table class="widefat"><thead><tr><th>IP Hash (Anonymous)</th><th>Target URI</th><th>Time</th><th>Notes</th></tr></thead><tbody>';
                    if (details.evidence && details.evidence.length > 0) {
                        details.evidence.forEach(function (ev) {
                            const ipHashShort = ev.ip_hash.substring(0, 12) + '...';
                            const timeAgo = new Date(ev.timestamp * 1000).toLocaleString();
                            let notesCell = '-';
                            if (ev.is_impersonator) {
                                notesCell = '<strong style="color: red;">Impersonator</strong>';
                            }
                            detailsHtml += `<tr><td><code title="${ev.ip_hash}">${ipHashShort}</code></td><td>${ev.request_uri}</td><td>${timeAgo}</td><td>${notesCell}</td></tr>`;
                        });
                    } else {
                        detailsHtml += '<tr><td colspan="3">No evidence found.</td></tr>';
                    }
                    detailsHtml += '</tbody></table>';

                    modal.find('.details-content').html(detailsHtml);
                } else {
                    modal.find('.details-content').html('<p>Error retrieving details.</p>');
                }
            }).fail(function () {
                modal.find('.details-content').html('<p>AJAX error.</p>');
            }).always(function () {
                modal.find('.advaipbl-loader-wrapper').hide();
                modal.find('.details-content').show();
            });
        });

        modal.find('.advaipbl-modal-cancel').on('click', function () {
            modal.fadeOut('fast');
        });

        // Lógica para el botón "Copy Hash"
        $('body').on('click', '.advaipbl-copy-hash', function (e) {
            e.preventDefault();
            const hashToCopy = $(this).data('hash');
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(hashToCopy)
                    .then(() => {
                        const originalText = $(this).text();
                        $(this).text('Copied!').prop('disabled', true);
                        setTimeout(() => {
                            $(this).text(originalText).prop('disabled', false);
                        }, 1500);
                    })
                    .catch(err => {
                        alert('Failed to copy text: ' + err);
                    });
            } else {
                // Fallback para navegadores antiguos (no recomendado para producción)
                const tempInput = $('<input>');
                $('body').append(tempInput);
                tempInput.val(hashToCopy).select();
                document.execCommand('copy');
                tempInput.remove();
                alert('Hash copied to clipboard!');
            }
        });

        $('body').on('click', '.advaipbl-whitelist-signature', function (e) {
            e.preventDefault();
            const $button = $(this);
            const $row = $button.closest('tr');
            const hash = $row.data('hash');

            $row.css('opacity', '0.5');
            $button.prop('disabled', true);

            $.post(ajaxurl, {
                action: 'advaipbl_whitelist_signature',
                nonce: adminData.nonces.whitelist_signature,
                hash: hash
            }).done(function (response) {
                if (response.success) {
                    $row.fadeOut('slow', function () { $(this).remove(); });
                } else {
                    showAdminNotice(response.data.message || 'An unknown error occurred.', 'error');
                    $row.css('opacity', '1');
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
                $row.css('opacity', '1');
                $button.prop('disabled', false);
            });
        });

    }

    function initPerPageSelector() { $('body').on('change', '.advaipbl-per-page-selector', function () { const $form = $(this).closest('form'); if ($form.length) { $form.get(0).submit(); } }); }
    function initApiVerification() {
        $('body').on('click', '.advaipbl-verify-api-key', function (e) {
            e.preventDefault();
            const $button = $(this);
            const provider = $button.data('provider');
            const keyId = $button.data('key-id');
            const apiKey = $('#' + keyId).val();
            const $status = $button.siblings('.advaipbl-api-status');
            const texts = adminData.text || {};

            $status.text(texts.verifying_api || 'Verifying...').css('color', '');
            $button.prop('disabled', true);

            if (!apiKey) {
                $status.text(texts.enter_api_key || 'Please enter an API key.').css('color', 'orange');
                $button.prop('disabled', false);
                return;
            }
            // Determinamos dinámicamente qué acción AJAX y nonce usar
            let ajaxAction = 'advaipbl_verify_api_key'; // Acción por defecto para Geolocation
            let nonce = adminData.nonces.verify_api;

            if (provider === 'abuseipdb') {
                ajaxAction = 'advaipbl_verify_abuseipdb_key';
                nonce = adminData.nonces.verify_abuseipdb;
            }

            $.post(ajaxurl, {
                action: ajaxAction,
                nonce: nonce,
                provider: provider, // Se sigue enviando por si el backend lo necesita
                api_key: apiKey
            })
                .done(function (response) {
                    if (response.success) {
                        $status.text(response.data.message).css('color', 'green');
                    } else {
                        $status.text('Error: ' + response.data.message).css('color', 'red');
                    }
                })
                .fail(function () {
                    $status.text(texts.ajax_error || 'AJAX error.').css('color', 'red');
                })
                .always(function () {
                    $button.prop('disabled', false);
                });
        });
    }
    function initAdminMenuCounter() { if (typeof adminData.counts === 'undefined' || typeof adminData.counts.blocked === 'undefined') { return; } const blockedCount = adminData.counts.blocked; if (blockedCount > 0) { const menuLink = $('ul#adminmenu a[href="options-general.php?page=advaipbl_settings_page"]'); if (menuLink.length) { const counterHtml = ` <span class="update-plugins count-${blockedCount}"><span class="plugin-count">${blockedCount}</span></span>`; menuLink.append(counterHtml); } } }
    function initFloatingSaveBar() {
        const $form = $('form[action="options.php"]'); if (!$form.length) { return; } const $saveBar = $('#advaipbl-floating-save-bar'); const $discardButton = $('#advaipbl-discard-changes'); const $saveButtonFloating = $('#advaipbl-save-changes-floating'); const $originalSaveButton = $form.find('input[type="submit"][name="submit"]'); let isDirty = false; let isSubmitting = false; const showBar = () => { if (!isDirty) { isDirty = true; $saveBar.removeClass('advaipbl-save-bar-hidden').addClass('advaipbl-save-bar-visible'); } }; const hideBar = () => { isDirty = false; $saveBar.removeClass('advaipbl-save-bar-visible').addClass('advaipbl-save-bar-hidden'); }; $form.on('change keyup', 'input, select, textarea', showBar); $saveButtonFloating.on('click', function (e) { e.preventDefault(); isSubmitting = true; $originalSaveButton.click(); }); $discardButton.on('click', function () { showConfirmModal({ title: adminData.text.discard_title || 'Discard Changes?', message: adminData.text.discard_message || 'You have unsaved changes. Are you sure you want to discard them?', confirmText: adminData.text.discard_confirm_btn || 'Yes, Discard', onConfirm: function () { isSubmitting = true; location.reload(); } }); }); $form.on('submit', function () { isSubmitting = true; hideBar(); }); $(window).on('beforeunload', function (e) {
            // Buscamos la variable global que creamos en initTwoFactorAuthProfile
            const isSubmitting2FA = window.advaipbl_isSubmittingAjax || false;

            if (isDirty && !isSubmitting && !isSubmitting2FA) {
                const confirmationMessage = 'You have unsaved changes that will be lost.';
                e.returnValue = confirmationMessage;
                return confirmationMessage;
            }
        });
    }
    function initLogFilterSelector() { const $logFilter = $('#advaipbl-log-filter'); if (!$logFilter.length) { return; } $logFilter.on('change', function () { const $form = $(this).closest('form'); if ($form.length) { $form.submit(); } }); }
    function initClearLogModal() { const $openButton = $('#advaipbl-open-clear-log-modal'); if (!$openButton.length) { return; } const $modal = $('#advaipbl-clear-log-modal'); const $checkboxContainer = $('#advaipbl-log-types-checkboxes'); $openButton.on('click', function () { $checkboxContainer.empty(); let checkboxesHtml = ''; let availableLogTypes = {}; const $logFilter = $('#advaipbl-log-filter'); if ($logFilter.length) { $logFilter.find('option').each(function () { const value = $(this).val(); const text = $(this).text(); if (value && value !== 'all') { availableLogTypes[value] = text; } }); } availableLogTypes['general'] = 'General Log'; availableLogTypes['wp_cron'] = 'WP-Cron Log'; for (const [value, text] of Object.entries(availableLogTypes)) { checkboxesHtml += `<p><label><input type="checkbox" name="log_types_to_clear[]" value="${value}"> ${text}</label></p>`; } $checkboxContainer.html(checkboxesHtml); $modal.fadeIn('fast'); }); $modal.find('.advaipbl-modal-cancel').on('click', function () { $modal.fadeOut('fast'); }); }

    /**
     * Maneja la lógica de la sección 2FA en la página de perfil de usuario.
     */
    function initTwoFactorAuthProfile() {
        $(document).on('click', '#advaipbl-2fa-activate-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section').data('user-id');
            const setupContainer = $('#advaipbl-2fa-setup-container');

            $button.prop('disabled', true);
            setupContainer.slideDown();
            setupContainer.find('.advaipbl-loader-wrapper').show();
            setupContainer.find('.advaipbl-setup-content').hide();

            $.post(ajaxurl, {
                action: 'advaipbl_2fa_generate',
                nonce: $button.data('nonce'),
                user_id: userId
            }).done(function (response) {
                if (response.success) {
                    $('#advaipbl-qr-code-wrapper').html(`<img src="${response.data.qr_url}" alt="QR Code">`);
                    $('#advaipbl-secret-key').text(response.data.secret);
                    let backupCodesHtml = '';
                    response.data.backup_codes.forEach(code => {
                        backupCodesHtml += `<code>${code}</code>`;
                    });
                    $('#advaipbl-backup-codes-wrapper').html(backupCodesHtml);
                    setupContainer.find('.advaipbl-setup-content').data('backup-codes', response.data.backup_codes);
                    setupContainer.find('.advaipbl-loader-wrapper').hide();
                    setupContainer.find('.advaipbl-setup-content').slideDown();
                } else {
                    showAdminNotice(response.data.message || 'Failed to generate 2FA secret.', 'error');
                    setupContainer.slideUp();
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
                setupContainer.slideUp();
                $button.prop('disabled', false);
            });
        });

        $(document).on('click', '#advaipbl-2fa-finalize-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section-wrapper').find('#advaipbl-2fa-section').data('user-id');
            const setupContent = $('#advaipbl-2fa-setup-container .advaipbl-setup-content');
            const feedbackSpan = $('#advaipbl-2fa-feedback');
            const code = $('#advaipbl-2fa-verify-code').val();
            const backupCodes = setupContent.data('backup-codes');

            if (!code || code.length !== 6 || !/^\d+$/.test(code)) {
                feedbackSpan.text('Please enter a valid 6-digit code.').css('color', 'red'); return;
            }
            $button.prop('disabled', true);
            feedbackSpan.text('Verifying...').css('color', '');

            $.post(ajaxurl, {
                action: 'advaipbl_2fa_activate',
                nonce: $button.data('nonce'),
                user_id: userId,
                code: code,
                backup_codes: backupCodes
            }).done(function (response) {
                if (response.success) {
                    feedbackSpan.text('Success! Reloading page...').css('color', 'green');
                    $(window).off('beforeunload');
                    setTimeout(() => window.location.reload(), 500);
                } else {
                    feedbackSpan.text(response.data.message || 'Verification failed.').css('color', 'red');
                    $button.prop('disabled', false);
                }
            }).fail(function () {
                feedbackSpan.text(adminData.text.ajax_error).css('color', 'red');
                $button.prop('disabled', false);
            });
        });

        $(document).on('click', '#advaipbl-2fa-cancel-btn', function () {
            $('#advaipbl-2fa-setup-container').slideUp();
            $('#advaipbl-2fa-activate-btn').prop('disabled', false);
        });

        $(document).on('click', '#advaipbl-2fa-deactivate-btn', function () {
            const $button = $(this);
            const userId = $button.closest('#advaipbl-2fa-section').data('user-id');
            showConfirmModal({
                title: 'Deactivate Two-Factor Authentication?',
                message: 'Are you sure you want to deactivate 2FA? Your account will be less secure.',
                confirmText: 'Yes, Deactivate',
                onConfirm: function () {
                    $button.prop('disabled', true).text('Deactivating...');
                    $.post(ajaxurl, {
                        action: 'advaipbl_2fa_deactivate',
                        nonce: $button.data('nonce'),
                        user_id: userId
                    }).done(function (response) {
                        if (response.success) {
                            $(window).off('beforeunload');
                            window.location.reload();
                        } else {
                            showAdminNotice(response.data.message || 'Failed to deactivate 2FA.', 'error');
                            $button.prop('disabled', false).text('Deactivate 2FA');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        $button.prop('disabled', false).text('Deactivate 2FA');
                    });
                }
            });
        });
    }

    /**
* Corrige el método del formulario y añade confirmación a las acciones en la tabla de usuarios 2FA.
*/
    function initTwoFactorUserTableForm() {
        const form = $('#advaipbl-2fa-users-form');
        if (!form.length) return;

        // 1. Manejo de filtros y búsqueda (necesitan GET)
        $('#filter_action, #search-submit').on('click', function (e) {
            // Prevenimos el envío normal
            e.preventDefault();

            // Cogemos los valores de los filtros
            const role = $('select[name="role"]').val();
            const search = $('input[name="s"]').val();

            // Construimos la URL con los parámetros correctos
            let currentUrl = window.location.href.split('?')[0];
            let params = new URLSearchParams();
            params.set('page', 'advaipbl_settings_page');
            params.set('tab', 'settings');
            params.set('sub-tab', '2fa_management');
            if (role) {
                params.set('role', role);
            }
            if (search) {
                params.set('s', search);
            }

            // Redirigimos
            window.location.href = currentUrl + '?' + params.toString();
        });

        // 2. Manejo de acciones en lote (necesitan POST y confirmación)
        $('input#doaction, input#doaction2').on('click', function (e) {
            e.preventDefault();

            const actionSelector = $(this).siblings('select[name^="action"]');
            const action = actionSelector.val();

            if (action === 'advaipbl_reset_2fa_bulk') {
                const checkedItems = form.find('input[name="users[]"]:checked');
                if (checkedItems.length === 0) {
                    alert('Please select at least one user.'); // Podemos traducir esto más tarde
                    return;
                }

                showConfirmModal({
                    title: 'Confirm Bulk Reset',
                    message: `Are you sure you want to reset 2FA for the selected ${checkedItems.length} user(s)? This action cannot be undone.`,
                    confirmText: 'Yes, Reset 2FA',
                    onConfirm: function () {
                        form.attr('method', 'post').submit();
                    }
                });
            }
        });

        // 3. Manejo del botón de reset individual (necesita confirmación)
        $('a.button[href*="action=advaipbl_reset_2fa"]').on('click', function (e) {
            e.preventDefault();
            const url = $(this).attr('href');

            showConfirmModal({
                title: 'Confirm Reset',
                message: 'Are you sure you want to reset 2FA for this user? They will be able to log in without a code.',
                confirmText: 'Yes, Reset 2FA',
                onConfirm: function () {
                    window.location.href = url;
                }
            });
        });
    }

    /**
* Maneja toda la lógica de visibilidad de las opciones de Geolocalización.
* Muestra/oculta las opciones de API vs. DB, y también los campos de API individuales.
*/
    function initGeolocationOptionsToggle() {
        const methodSelector = $('#advaipbl_geolocation_method');
        const providerSelector = $('#advaipbl_geolocation_provider_select'); // El desplegable de proveedores de API

        if (!methodSelector.length) return;

        // Función que actualiza la visibilidad de los campos de API individuales
        const toggleApiProviderFields = function () {
            const selectedProvider = providerSelector.val();
            // Ocultamos todos los campos de clave de API primero
            $('.api-key-field').closest('tr').hide();
            // Luego mostramos solo el que corresponde al proveedor seleccionado
            if (selectedProvider) {
                $(`input[data-provider="${selectedProvider}"]`).closest('tr').show();
            }
        };

        // Función principal que actualiza la visibilidad general
        const toggleOptionsVisibility = function () {
            const selectedMethod = methodSelector.val();

            if (selectedMethod === 'api') {
                $('.advaipbl-geolocation-api-option').closest('tr').show();
                $('.advaipbl-geolocation-db-option').closest('tr').hide();
                // Una vez que mostramos el bloque de API, llamamos a la función
                // que se encarga de los campos individuales.
                toggleApiProviderFields();
            } else if (selectedMethod === 'local_db') {
                $('.advaipbl-geolocation-api-option').closest('tr').hide();
                $('.advaipbl-geolocation-db-option').closest('tr').show();
            }
        };

        // Ejecutar al cargar la página
        toggleOptionsVisibility();

        // Registrar los eventos de cambio
        methodSelector.on('change', toggleOptionsVisibility);
        providerSelector.on('change', toggleApiProviderFields); // El selector de proveedor solo necesita actualizar los campos de API
    }

    /**
* Maneja el botón para actualizar la base de datos GeoIP.
*/
    function initGeoIpDownloader() {
        $('body').on('click', '#advaipbl-update-geoip-db', function () {
            const $button = $(this);
            const $feedback = $('#advaipbl-geoip-update-feedback');
            const originalText = $button.text();

            $button.prop('disabled', true).text('Updating...');
            $feedback.text('Starting update process...').css('color', '');

            $.post(ajaxurl, {
                action: 'advaipbl_update_geoip_db',
                nonce: $button.data('nonce')
            })
                .done(function (response) {
                    if (response.success) {
                        $feedback.text(response.data.message).css('color', 'green');
                        // Desactivamos el aviso de "cambios sin guardar" antes de recargar.
                        $(window).off('beforeunload');

                        setTimeout(() => window.location.reload(), 2000);
                    } else {
                        $feedback.text('Error: ' + (response.data.message || 'Unknown error')).css('color', 'red');
                        $button.prop('disabled', false).text(originalText);
                    }
                })
                .fail(function () {
                    $feedback.text(adminData.text.ajax_error).css('color', 'red');
                    $button.prop('disabled', false).text(originalText);
                });
        });
    }

    /**
 * Inicializa la navegación lateral en la página de ajustes.
 * Gestiona el scroll suave y el resaltado activo del menú (spy-scroll).
 */
    function initSettingsSideNav() {
        const $nav = $('.advaipbl-settings-nav');
        if (!$nav.length) {
            return;
        }

        const $navLinks = $nav.find('a');
        const $sections = $('.advaipbl-settings-section');
        const offsetTop = 100; // Espacio desde la parte superior para el resaltado

        // Scroll suave al hacer clic en un enlace del menú
        $navLinks.on('click', function (e) {
            e.preventDefault();
            const targetId = $(this).attr('href');
            const $target = $(targetId);
            if ($target.length) {
                $('html, body').animate({
                    scrollTop: $target.offset().top - offsetTop + 20
                }, 300);
            }
        });

        // Spy-scroll para resaltar el enlace activo
        $(window).on('scroll', function () {
            const scrollPos = $(document).scrollTop();

            $sections.each(function () {
                const $currentSection = $(this);
                const sectionTop = $currentSection.offset().top - offsetTop;
                const sectionBottom = sectionTop + $currentSection.outerHeight();

                if (scrollPos >= sectionTop && scrollPos < sectionBottom) {
                    const id = $currentSection.attr('id');
                    $navLinks.removeClass('active');
                    $nav.find('a[href="#' + id + '"]').addClass('active');
                }
            });

            // Resaltar el último si se llega al final de la página (casi al final)
            if ($(window).scrollTop() + $(window).height() > $(document).height() - 5) {
                $navLinks.removeClass('active');
                $navLinks.last().addClass('active');
            }
            // Resaltar el primero si se está al principio
            if ($(window).scrollTop() < $sections.first().offset().top - offsetTop) {
                $navLinks.removeClass('active');
                $navLinks.first().addClass('active');
            }
        }).scroll(); // Ejecutar una vez al cargar la página
    }

    /**
 * Maneja las acciones en la tabla de Endpoint Lockdowns (Cancelar y Ver Detalles).
 */
    function initEndpointLockdownActions() {
        const $container = $('.advaipbl-tab-content');

        // Acción de Cancelar Lockdown
        $container.on('click', '.advaipbl-delete-lockdown', function (e) {
            e.preventDefault();
            const $button = $(this);
            const url = $button.attr('href');
            const endpointName = $button.closest('tr').find('td:first-child code').text();

            showConfirmModal({
                title: 'Cancel Lockdown?',
                message: `Are you sure you want to cancel the lockdown for the <strong>${endpointName}</strong> endpoint? This will immediately allow all traffic to be processed again.`,
                confirmText: 'Yes, Cancel Lockdown',
                onConfirm: function () {
                    window.location.href = url;
                }
            });
        });

        // Acción para Ver Detalles
        const modal = $('#advaipbl-lockdown-details-modal');
        $container.on('click', '.advaipbl-view-lockdown-details', function (e) {
            e.preventDefault();
            const lockdownId = $(this).closest('tr').data('lockdown-id');
            const endpointName = $(this).closest('tr').find('td:first-child code').text();

            modal.find('.advaipbl-modal-title').html(`Lockdown Details: <code>${endpointName}</code>`);
            modal.find('.details-content').hide().empty();
            modal.find('.advaipbl-loader-wrapper').show();
            modal.fadeIn('fast');

            $.post(ajaxurl, {
                action: 'advaipbl_get_lockdown_details',
                nonce: adminData.nonces.get_lockdown_details,
                id: lockdownId
            }).done(function (response) {
                if (response.success && response.data.details) {
                    const details = response.data.details;
                    const ipDetails = details.details ? JSON.parse(details.details) : {};
                    const triggeringHashes = ipDetails.triggering_ip_hashes || [];

                    let detailsHtml = `<h4>${details.reason}</h4>`;
                    detailsHtml += '<p>This lockdown was triggered by repeated blocks from the following IP Hashes (sample, anonymized for privacy):</p>';

                    if (triggeringHashes.length > 0) {
                        detailsHtml += '<ul class="ul-disc">';
                        triggeringHashes.forEach(hash => {
                            // Mostramos una versión acortada del hash
                            detailsHtml += `<li><code>${hash.substring(0, 12)}...</code></li>`;
                        });
                        detailsHtml += '</ul>';
                    } else {
                        detailsHtml += '<p>No specific triggering IP hashes were recorded.</p>';
                    }

                    // --- NEW: Render Request Samples ---
                    if (ipDetails.samples && ipDetails.samples.length > 0) {
                        detailsHtml += '<hr><h5>Recent Attack Samples (Last 20)</h5>';
                        detailsHtml += '<div style="max-height: 250px; overflow-y: auto; border: 1px solid #ddd;">';
                        detailsHtml += '<table class="widefat striped" style="border:none;">';
                        detailsHtml += '<thead><tr><th style="width:140px;">Time</th><th>URI</th><th>User-Agent</th></tr></thead>';
                        detailsHtml += '<tbody>';

                        ipDetails.samples.forEach(sample => {
                            // Sanitize output for safety
                            const time = sample.time || 'N/A';
                            const uri = $('<div>').text(sample.uri).html();
                            const ua = $('<div>').text(sample.ua).html();
                            detailsHtml += `<tr>
                                <td>${time}</td>
                                <td style="word-break: break-all;"><code>${uri}</code></td>
                                <td style="font-size: 11px; color:#666;">${ua}</td>
                            </tr>`;
                        });

                        detailsHtml += '</tbody></table></div>';
                    }

                    modal.find('.details-content').html(detailsHtml);
                } else {
                    modal.find('.details-content').html(`<p>${response.data.message || 'Error retrieving details.'}</p>`);
                }
            }).fail(function () {
                modal.find('.details-content').html('<p>AJAX error.</p>');
            }).always(function () {
                modal.find('.advaipbl-loader-wrapper').hide();
                modal.find('.details-content').show();
            });
        });

        // Evento de cierre específico para este modal
        modal.find('.advaipbl-modal-cancel').on('click', function () {
            modal.fadeOut('fast');
        });
    }

    /**
 * Inicializa todos los selectores de países con Select2.
 */
    function initCountrySelectors() {
        if (typeof $.fn.select2 !== 'function') return;

        $('.advaipbl-country-select').each(function () {
            const $selector = $(this);
            // Usamos el data-placeholder que definimos en PHP
            const placeholder = $selector.data('placeholder') || 'Search for a country...';

            $selector.select2({
                placeholder: placeholder,
                width: '100%',
                maximumSelectionLength: 100
            });
        });
    }

    /**
     * Inicializa las acciones para el Audit Log (limpieza manual).
     */
    function initAuditLogActions() {
        $('#advaipbl-clear-audit-logs-btn').on('click', function (e) {
            e.preventDefault();
            const btn = $(this);
            const nonce = btn.data('nonce');

            showConfirmModal({
                title: 'Clear Audit Logs?',
                message: 'Are you sure you want to delete <strong>ALL</strong> activity audit logs? This action cannot be undone.',
                confirmText: 'Yes, Clear All Logs',
                onConfirm: function () {
                    btn.prop('disabled', true).text('Clearing...');
                    $.post(ajaxurl, {
                        action: 'advaipbl_clear_audit_logs',
                        nonce: nonce
                    }).done(function (response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert(response.data.message || 'Error clearing logs.');
                            btn.prop('disabled', false).text('Clear Audit Log');
                        }
                    }).fail(function () {
                        alert('AJAX error.');
                        btn.prop('disabled', false).text('Clear Audit Log');
                    });
                }
            });
        });
    }

    /**
     * Inicializa el buscador inteligente en la página de ajustes generales.
     * Estrategia: Mostrar TARJETAS COMPLETAS si hay alguna coincidencia dentro.
     */
    function initSettingsSearch() {
        const searchInput = $('#advaipbl-settings-search');
        if (!searchInput.length) { return; }

        const sideMenu = $('.advaipbl-settings-nav');
        const noResultsMessage = $('.no-results-message');

        searchInput.on('keyup', function () {
            const term = $(this).val().toLowerCase().trim();

            // 1. Resetear todo si está vacío
            if (term === '') {
                $('.advaipbl-settings-section, .advaipbl-card').show();
                sideMenu.find('li').show();
                noResultsMessage.hide();
                return;
            }

            let globalMatch = false;

            $('.advaipbl-settings-section').hide();
            sideMenu.find('li').hide();

            $('.advaipbl-settings-section').each(function () {
                const $section = $(this);
                const sectionId = $section.attr('id');
                let sectionHasMatch = false;

                // 4. Iterar por cada TARJETA dentro de la sección
                $section.find('.advaipbl-card').each(function () {
                    const $card = $(this);

                    // Buscamos en TODO el texto de la tarjeta (títulos, labels, descripciones, valores)

                    const cardText = $card.text().toLowerCase();

                    // Búsqueda también en valores de inputs (útil para IPs o claves API)
                    let inputsText = "";
                    $card.find('input[type="text"], textarea').each(function () {
                        inputsText += $(this).val().toLowerCase() + " ";
                    });

                    if (cardText.includes(term) || inputsText.includes(term)) {
                        $card.show();
                        sectionHasMatch = true;
                    } else {
                        // No coincide, ocultamos la tarjeta
                        $card.hide();
                    }
                });

                // Si la sección tiene al menos una tarjeta visible, mostramos la sección y el menú
                if (sectionHasMatch) {
                    $section.show();
                    globalMatch = true;
                    if (sectionId) {
                        sideMenu.find(`a[href="#${sectionId}"]`).parent().show();
                    }
                }
            });


            noResultsMessage.toggle(!globalMatch);
        });
    }

    // ========================================================================
    // LÓGICA PARA EL MOTOR DE REGLAS AVANZADO
    // ========================================================================

    function initializeAdvancedRules() {
        const rulesListContainer = $('#advaipbl-advanced-rules-list');
        const navContainers = $('.advaipbl-rules-nav-bar');
        if (!rulesListContainer.length) {
            return;
        }

        const modal = $('#advaipbl-rule-builder-modal');
        const conditionTemplate = $('#advaipbl-condition-template').html();
        const conditionsContainer = $('#advaipbl-rule-conditions');

        const operators = {
            string: [{ value: 'is', text: 'is' }, { value: 'is_not', text: 'is not' }, { value: 'contains', text: 'contains' }, { value: 'does_not_contain', text: 'does not contain' }, { value: 'starts_with', text: 'starts with' }, { value: 'ends_with', text: 'ends with' }, { value: 'matches_regex', text: 'matches regex' }],
            ip: [{ value: 'is', text: 'is' }, { value: 'is_not', text: 'is not' }],
            ip_range: [{ value: 'is', text: 'is in range' }, { value: 'is_not', text: 'is not in range' }]
        };

        function updateOperatorDropdown(conditionRow) {
            const type = conditionRow.find('.condition-type').val();
            const operatorDropdown = conditionRow.find('.condition-operator');
            let ops = [...operators.string];
            if (type === 'ip') ops = [...operators.ip];
            if (type === 'ip_range' || type === 'country' || type === 'asn') ops = [...operators.ip_range];
            if (type === 'country' || type === 'asn') {
                const isOp = ops.find(op => op.value === 'is'); if (isOp) isOp.text = 'is';
                const isNotOp = ops.find(op => op.value === 'is_not'); if (isNotOp) isNotOp.text = 'is not';
            }
            operatorDropdown.empty();
            ops.forEach(op => operatorDropdown.append($('<option>', { value: op.value, text: op.text })));
        }

        function updateValueInput(conditionRow) {
            const type = conditionRow.find('.condition-type').val();
            const valueContainer = conditionRow.find('.condition-value-container');
            valueContainer.empty();
            if (type === 'country') {
                const select = $('<select>', { class: 'condition-value', style: 'width: 100%;' });
                select.append(new Option('', '', false, false));
                if (adminData.countries) {
                    for (const [code, name] of Object.entries(adminData.countries)) {
                        select.append(new Option(name, code, false, false));
                    }
                }
                valueContainer.append(select);
                select.select2({ dropdownParent: modal, placeholder: 'Search for a country...', closeOnSelect: true });
            } else {
                let placeholder = 'e.g., /admin/login.php';
                if (type === 'ip') placeholder = 'e.g., 1.2.3.4';
                if (type === 'ip_range') placeholder = 'e.g., 1.2.3.0/24';
                if (type === 'asn') placeholder = 'e.g., AS15169';
                if (type === 'user_agent') placeholder = 'e.g., BadBot/1.0';
                if (type === 'username') placeholder = 'e.g., admin';
                valueContainer.append($('<input>', { type: 'text', class: 'condition-value', placeholder: placeholder }));
            }
        }

        function addConditionRow(condition = {}) {
            const newRow = $(conditionTemplate);
            conditionsContainer.append(newRow);
            updateOperatorDropdown(newRow);
            updateValueInput(newRow);
            if (condition.type) {
                newRow.find('.condition-type').val(condition.type);
                updateOperatorDropdown(newRow);
                updateValueInput(newRow);
                newRow.find('.condition-operator').val(condition.operator);
                if (condition.type === 'country') {
                    newRow.find('.condition-value').val(condition.value).trigger('change');
                } else {
                    newRow.find('.condition-value').val(condition.value);
                }
            }
        }

        function updateActionParams() {
            const action = $('#advaipbl-rule-action').val();
            const paramsContainer = $('#advaipbl-rule-action-params');
            paramsContainer.empty();
            $('#advaipbl-rule-action-params-row').show();
            if (action === 'block') {
                paramsContainer.html('<input type="number" id="param-duration" class="small-text" min="0"> minutes. <span class="description">(Set to 0 for a permanent block)</span>');
            } else if (action === 'score') {
                paramsContainer.html('<input type="number" id="param-points" class="small-text" min="1" value="10"> points.');
            } else {
                $('#advaipbl-rule-action-params-row').hide();
            }
        }

        function renderRule(rule) {
            let conditionsHtml = rule.conditions.map(c => `<li><span class="rule-component-type">${c.type.replace('_', ' ')}</span> <span class="rule-component-operator">${c.operator.replace('_', ' ')}</span> <code class="rule-component-value">${c.value}</code></li>`).join('');
            let actionHtml = `<span class="rule-action-type" data-action="${rule.action}">${rule.action}</span>`;
            if (rule.action_params) {
                if (rule.action_params.duration !== undefined) actionHtml += ` <span class="rule-action-param">(${rule.action_params.duration > 0 ? rule.action_params.duration + ' min' : 'permanent'})</span>`;
                if (rule.action_params.points) actionHtml += ` <span class="rule-action-param">(+${rule.action_params.points} pts)</span>`;
            }

            return `
        <div class="advaipbl-rule-card" data-rule-id="${rule.id}">
            <div class="rule-selector"><input type="checkbox" class="rule-checkbox"></div>
            <div class="rule-name"><strong>${rule.name}</strong></div>
            <div class="rule-summary">
                <strong>IF:</strong> ${conditionsHtml}
            </div>
            <div class="rule-action">
                <strong>THEN:</strong> ${actionHtml}
            </div>
            <div class="rule-actions">
                <button class="button button-secondary move-rule-up" title="Move Up"><span class="dashicons dashicons-arrow-up-alt2"></span></button>
                <button class="button button-secondary move-rule-down" title="Move Down"><span class="dashicons dashicons-arrow-down-alt2"></span></button>
                <button class="button button-secondary edit-rule">Edit</button>
                <button class="button button-link-delete delete-rule">Delete</button>
            </div>
        </div>`;
        }

        function renderPagination(pagination) {
            const paginationContainers = $('.advaipbl-pagination-container');
            paginationContainers.empty();
            if (pagination.total_pages <= 1) {
                if (pagination.total_items > 0) {
                    paginationContainers.html(`<div class="tablenav-pages one-page"><span class="displaying-num">${pagination.total_items} items</span></div>`);
                }
                return;
            }
            const paginationHtml = `<div class="tablenav-pages"><span class="displaying-num">${pagination.total_items} items</span><span class="pagination-links"><a class="prev-page button ${pagination.current_page <= 1 ? 'disabled' : ''}" href="#" data-page="${pagination.current_page - 1}">‹</a><span class="screen-reader-text">Current Page</span><span class="paging-input"><span class="tablenav-paging-text">${pagination.current_page} of <span class="total-pages">${pagination.total_pages}</span></span></span><a class="next-page button ${pagination.current_page >= pagination.total_pages ? 'disabled' : ''}" href="#" data-page="${pagination.current_page + 1}">›</a></span></div>`;
            paginationContainers.html(paginationHtml);
        }

        function loadRules(page = 1) {
            // navContainers defined in parent scope

            rulesListContainer.html('<div class="advaipbl-loader-wrapper"><div class="advaipbl-loader"></div></div>');
            navContainers.hide(); // Ocultamos toda la barra por defecto

            $.post(ajaxurl, {
                action: 'advaipbl_get_advanced_rules',
                nonce: adminData.nonces.get_rules_nonce,
                page: page
            }).done(function (response) {
                rulesListContainer.empty();
                if (response.success) {
                    if (response.data.rules && response.data.rules.length > 0) {
                        // Si hay reglas, mostramos la barra y renderizamos todo
                        navContainers.show();
                        response.data.rules.forEach(rule => {
                            rulesListContainer.append(renderRule(rule));
                        });
                        renderPagination(response.data.pagination);
                    } else {
                        // Si no hay reglas, las barras permanecen ocultas y mostramos el mensaje.
                        rulesListContainer.html(`<p>${adminData.text.no_advanced_rules || 'No advanced rules have been created yet.'}</p>`);
                    }
                } else {
                    // En caso de error, las barras permanecen ocultas.
                    rulesListContainer.html(`<p class="error">${adminData.text.could_not_load_rules || 'Could not load rules.'}</p>`);
                }
            }).fail(function () {
                // En caso de fallo de AJAX, las barras permanecen ocultas.
                navContainers.hide();
                rulesListContainer.html(`<p class="error">${adminData.text.ajax_error || 'An AJAX error occurred.'}</p>`);
            });
        }

        $('#advaipbl-add-new-rule-btn').on('click', function () { modal.find('.advaipbl-modal-title').text('Add New Rule'); $('#advaipbl-rule-id').val(''); $('#advaipbl-rule-name').val(''); conditionsContainer.empty(); addConditionRow(); updateActionParams(); modal.show(); });
        modal.on('click', '.advaipbl-modal-cancel', function () { modal.hide(); });
        conditionsContainer.on('change', '.condition-type', function () { const row = $(this).closest('.advaipbl-condition-row'); updateOperatorDropdown(row); updateValueInput(row); });
        conditionsContainer.on('click', '.remove-condition', function () { $(this).closest('.advaipbl-condition-row').remove(); });
        $('#advaipbl-add-condition-btn').on('click', addConditionRow);
        $('#advaipbl-rule-action').on('change', updateActionParams);

        $('#advaipbl-save-rule-btn').on('click', function () { const button = $(this); button.prop('disabled', true); const feedback = $('#advaipbl-rule-builder-feedback'); feedback.text('Saving...').css('color', ''); const rule = { id: $('#advaipbl-rule-id').val(), name: $('#advaipbl-rule-name').val().trim(), conditions: [], action: $('#advaipbl-rule-action').val(), action_params: {} }; if (!rule.name) { feedback.text('Rule name is required.').css('color', 'red'); button.prop('disabled', false); return; } conditionsContainer.find('.advaipbl-condition-row').each(function () { const row = $(this); rule.conditions.push({ type: row.find('.condition-type').val(), operator: row.find('.condition-operator').val(), value: row.find('.condition-value').val() }); }); if (rule.action === 'block') rule.action_params.duration = parseInt($('#param-duration').val()) || 0; if (rule.action === 'score') rule.action_params.points = parseInt($('#param-points').val()) || 10; $.post(ajaxurl, { action: 'advaipbl_save_advanced_rule', nonce: adminData.nonces.save_rule_nonce, rule: JSON.stringify(rule) }).done(function (response) { if (response.success) { feedback.text(response.data.message).css('color', 'green'); setTimeout(() => { modal.hide(); loadRules(); }, 1000); } else { feedback.text(response.data.message).css('color', 'red'); } }).fail(function () { feedback.text('An AJAX error occurred.').css('color', 'red'); }).always(function () { button.prop('disabled', false); }); });
        rulesListContainer.on('click', '.delete-rule', function (e) {
            e.preventDefault();
            const card = $(this).closest('.advaipbl-rule-card');
            const ruleId = card.data('rule-id');
            const ruleName = card.find('.rule-name strong').text();

            showConfirmModal({
                title: adminData.text.delete_rule_confirm_title || 'Delete Rule?',
                message: (adminData.text.delete_rule_confirm_message || 'Are you sure you want to permanently delete the rule "%s"?').replace('%s', `<strong>${ruleName}</strong>`),
                confirmText: adminData.text.delete_rule_confirm_button || 'Yes, Delete Rule',
                onConfirm: function () {
                    card.css('opacity', '0.5');

                    $.post(ajaxurl, {
                        action: 'advaipbl_delete_advanced_rule',
                        nonce: adminData.nonces.delete_rule_nonce,
                        rule_id: ruleId
                    }).done(function (response) {
                        if (response.success) {
                            // Al borrar, recargamos la lista para que la paginación se actualice
                            const currentPage = parseInt($('.advaipbl-rules-nav-bar .paging-input .tablenav-paging-text').text().split(' ')[0]) || 1;
                            loadRules(currentPage);
                            showAdminNotice(response.data.message, 'success');
                        } else {
                            showAdminNotice(response.data.message || 'An unknown error occurred.', 'error');
                            card.css('opacity', '1');
                        }
                    }).fail(function () {
                        showAdminNotice(adminData.text.ajax_error, 'error');
                        card.css('opacity', '1');
                    });
                }
            });
        });
        rulesListContainer.on('click', '.edit-rule', function () { const card = $(this).closest('.advaipbl-rule-card'); const ruleId = card.data('rule-id'); $.post(ajaxurl, { action: 'advaipbl_get_advanced_rules', nonce: adminData.nonces.get_rules_nonce }, function (response) { if (response.success) { const ruleToEdit = response.data.rules.find(r => r.id === ruleId); if (ruleToEdit) { $('#advaipbl-rule-id').val(ruleToEdit.id); $('#advaipbl-rule-name').val(ruleToEdit.name); conditionsContainer.empty(); ruleToEdit.conditions.forEach(c => addConditionRow(c)); $('#advaipbl-rule-action').val(ruleToEdit.action); updateActionParams(); if (ruleToEdit.action === 'block') $('#param-duration').val(ruleToEdit.action_params.duration); if (ruleToEdit.action === 'score') $('#param-points').val(ruleToEdit.action_params.points); modal.find('.advaipbl-modal-title').text('Edit Rule'); modal.show(); } } }); });

        $('.advaipbl-rules-nav-bar').on('click', 'a.prev-page, a.next-page', function (e) {
            e.preventDefault();
            if ($(this).hasClass('disabled')) return;
            const page = $(this).data('page');
            loadRules(page);
        });


        const navs = $('.advaipbl-rules-nav-bar');

        // Sincronizar los selectores de arriba y abajo
        const topBulkSelector = navs.first().find('.advaipbl-adv-rules-bulk-action');
        const bottomBulkSelector = navs.last().find('.advaipbl-adv-rules-bulk-action');
        topBulkSelector.on('change', () => bottomBulkSelector.val(topBulkSelector.val()));
        bottomBulkSelector.on('change', () => topBulkSelector.val(topBulkSelector.val()));

        // Lógica del botón "Apply"
        navs.on('click', '.advaipbl-apply-bulk-action', function () {
            const action = $(this).siblings('select').val();
            if (action === '-1') {
                alert('Please select a bulk action.');
                return;
            }
            const selected_ids = [];
            rulesListContainer.find('.rule-checkbox:checked').each(function () {
                selected_ids.push($(this).closest('.advaipbl-rule-card').data('rule-id'));
            });
            if (selected_ids.length === 0) {
                alert('Please select at least one rule to apply the action.');
                return;
            }
            if (action === 'delete') {
                showConfirmModal({
                    title: adminData.text.bulk_delete_rules_confirm_title || 'Confirm Bulk Deletion',
                    message: (adminData.text.bulk_delete_rules_confirm_message || 'Are you sure you want to delete the selected %d rule(s)?').replace('%d', selected_ids.length),
                    confirmText: adminData.text.bulk_delete_rules_confirm_button || 'Yes, Delete Selected',
                    onConfirm: function () {
                        $.post(ajaxurl, {
                            action: 'advaipbl_bulk_delete_advanced_rules',
                            nonce: adminData.nonces.bulk_delete_rules_nonce,
                            rule_ids: selected_ids
                        }).done(function (response) {
                            if (response.success) {
                                showAdminNotice(response.data.message, 'success');
                                loadRules(1); // Recargar a la primera página
                            } else {
                                showAdminNotice(response.data.message, 'error');
                            }
                        }).fail(function () {
                            showAdminNotice(adminData.text.ajax_error, 'error');
                        });
                    }
                });
            }
        });

        // Lógica para el checkbox "Seleccionar todo"
        const selectAllTop = $('<input type="checkbox" class="advaipbl-rule-select-all">');
        const selectAllBottom = $('<input type="checkbox" class="advaipbl-rule-select-all">');
        navs.first().find('.bulkactions').prepend(selectAllTop);
        navs.last().find('.bulkactions').prepend(selectAllBottom);

        selectAllTop.add(selectAllBottom).on('change', function () {
            const isChecked = $(this).prop('checked');
            selectAllTop.prop('checked', isChecked);
            selectAllBottom.prop('checked', isChecked);
            rulesListContainer.find('.rule-checkbox').prop('checked', isChecked);
        });

        rulesListContainer.off('click', '.move-rule-up').on('click', '.move-rule-up', function () {
            const ruleId = $(this).closest('.advaipbl-rule-card').data('rule-id');
            moveRule(ruleId, 'up');
        });

        rulesListContainer.off('click', '.move-rule-down').on('click', '.move-rule-down', function () {
            const ruleId = $(this).closest('.advaipbl-rule-card').data('rule-id');
            moveRule(ruleId, 'down');
        });

        function moveRule(ruleId, direction) {
            // Mostrar algún indicador de carga si se desea, o simplemente esperar

            $.post(ajaxurl, {
                action: 'advaipbl_reorder_rules',
                nonce: adminData.nonces.reorder_rules_nonce,
                rule_id: ruleId,
                direction: direction
            }).done(function (response) {
                if (response.success) {
                    // Recargar reglas para mostrar nuevo orden
                    // Usar la página actual
                    const currentPage = parseInt($('.advaipbl-rules-nav-bar .paging-input .tablenav-paging-text').text().split(' ')[0]) || 1;
                    loadRules(currentPage);
                } else {
                    showAdminNotice(response.data.message || 'Error reordering rules.', 'error');
                }
            }).fail(function () {
                showAdminNotice(adminData.text.ajax_error, 'error');
            });
        }

        loadRules();
    }

    // Deep Scan Logic
    $('#advaipbl-run-deep-scan').on('click', function () {
        const btn = $(this);
        const nonce = btn.data('nonce');
        const statusDiv = $('#advaipbl-scan-message');
        const loadingDiv = $('#advaipbl-scan-loading');
        const resultsDiv = $('#advaipbl-scan-details');
        const iconDiv = $('#advaipbl-scan-status-icon');

        const text = advaipbl_admin_data.text;

        btn.hide();
        loadingDiv.show();
        resultsDiv.hide();
        statusDiv.html('<p>' + text.scan_checking + '</p>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_run_deep_scan',
                nonce: nonce
            },
            success: function (response) {
                loadingDiv.hide();
                btn.show().text(text.scan_again);

                if (response.success) {
                    const data = response.data;

                    if (data.status === 'clean') {
                        iconDiv.html('<span class="dashicons dashicons-yes-alt" style="color:green;"></span>');
                        statusDiv.html('<h3 style="color:green; margin:0;">' + text.scan_clean_title + '</h3><p>' + text.scan_clean_desc + '</p>');
                    } else if (data.status === 'vulnerable') {
                        iconDiv.html('<span class="dashicons dashicons-warning" style="color:#d63638;"></span>');

                        const title = text.scan_vuln_title.replace('%d', data.count);
                        statusDiv.html(`<h3 style="color:#d63638; margin:0;">${title}</h3><p>${text.scan_vuln_desc}</p>`);

                        let rows = '';
                        $.each(data.details, function (slug, info) {


                            const vuln = Array.isArray(info) ? info[0] : info;
                            if (!vuln) return;

                            const severityColor = (vuln.severity === 'Critical' || vuln.severity === 'High') ? '#d63638' : '#f59e0b';

                            // Sanitization Helper
                            const cleanText = (str) => {
                                if (!str) return '';
                                return str.replace(/Wordfence/gi, 'Security Provider').replace(/WordFence/g, 'Security Provider');
                            };

                            const title = cleanText(vuln.title);

                            // Improved Fix/Remediation extraction
                            let softwareInfo = (vuln.software && vuln.software.length > 0) ? vuln.software[0] : {};
                            let fix = cleanText(softwareInfo.remediation || vuln.fix || 'No known patch available.');

                            const description = cleanText(vuln.description || 'No description available.');
                            const cve = vuln.cve || '';
                            const cveLink = vuln.cve_link || '';
                            const cvss = vuln.cvss ? vuln.cvss.score : '';
                            const cvssVector = vuln.cvss ? vuln.cvss.vector : '';


                            // CVE HTML Construction
                            let cveHtml = '';
                            if (cve) {
                                if (cveLink) {
                                    cveHtml = `<div><strong>CVE:</strong> <a href="${cveLink}" target="_blank" rel="noopener"><code>${cve}</code></a></div>`;
                                } else {
                                    cveHtml = `<div><strong>CVE:</strong> <code>${cve}</code></div>`;
                                }
                            }

                            // Robust "Patched In" logic
                            let patched = 'N/A';
                            if (softwareInfo.patched_versions && softwareInfo.patched_versions.length > 0) {
                                patched = softwareInfo.patched_versions.join(', ');
                            } else if (softwareInfo.patched) {
                                patched = 'Yes';
                            } else {
                                // Fallback to checking remediation text if array is empty
                                patched = 'See remediation';
                            }

                            // Links
                            let linksHtml = '';
                            if (vuln.references && vuln.references.length > 0) {
                                linksHtml = '<strong>References:</strong><ul>';
                                vuln.references.forEach(ref => {
                                    linksHtml += `<li><a href="${ref}" target="_blank" rel="noopener">External Link <span class="dashicons dashicons-external"></span></a></li>`;
                                });
                                linksHtml += '</ul>';
                            }

                            // Main Row
                            rows += `<tr class="advaipbl-vuln-main-row">
                                <td><button type="button" class="button button-small advaipbl-toggle-vuln-details"><span class="dashicons dashicons-arrow-right-alt2"></span></button></td>
                                <td><strong>${slug}</strong></td>
                                <td><strong style="color:${severityColor}">${info.severity}</strong></td>
                                <td>${title}</td>
                                <td>${fix}</td>
                            </tr>`;

                            // Details Row
                            rows += `<tr class="advaipbl-vuln-details-row" style="display:none; background-color: #f9f9f9;">
                                <td colspan="5" style="padding: 15px;">
                                    <div class="advaipbl-vuln-details-content">
                                        <div style="display:flex; gap: 20px; margin-bottom: 10px;">
                                            ${cveHtml}
                                            ${cvss ? `<div><strong>CVSS Score:</strong> ${cvss}</div>` : ''}
                                            <div><strong>Patched In:</strong> ${patched}</div>
                                        </div>
                                        <p><strong>Description:</strong><br>${description}</p>
                                        ${linksHtml}
                                    </div>
                                </td>
                            </tr>`;
                        });
                        resultsDiv.find('tbody').html(rows);

                        // Toggle Logic
                        resultsDiv.off('click', '.advaipbl-toggle-vuln-details').on('click', '.advaipbl-toggle-vuln-details', function () {
                            const btn = $(this);
                            const icon = btn.find('.dashicons');
                            const mainRow = btn.closest('tr');
                            const detailsRow = mainRow.next('.advaipbl-vuln-details-row');

                            if (detailsRow.is(':visible')) {
                                detailsRow.hide();
                                icon.removeClass('dashicons-arrow-down-alt2').addClass('dashicons-arrow-right-alt2');
                            } else {
                                detailsRow.show();
                                icon.removeClass('dashicons-arrow-right-alt2').addClass('dashicons-arrow-down-alt2');
                            }
                        });

                        resultsDiv.show();
                    }
                } else {
                    statusDiv.html('<p style="color:red;">Error: ' + response.data.message + '</p>');
                }
            },
            error: function () {
                loadingDiv.hide();
                btn.show();
                statusDiv.html('<p style="color:red;">' + text.scan_error + '</p>');
            }
        });
    });

    // Server Reputation Check Logic
    $('#advaipbl-run-rep-check').on('click', function () {
        const btn = $(this);
        const nonce = btn.data('nonce');
        const statusDiv = $('#advaipbl-rep-message');
        const loadingDiv = $('#advaipbl-rep-loading');
        const resultsDiv = $('#advaipbl-rep-details');
        const iconDiv = $('#advaipbl-rep-status-icon');

        // Acceso a textos traducidos
        const text = advaipbl_admin_data.text;

        btn.hide();
        loadingDiv.show();
        resultsDiv.hide();
        statusDiv.html('<p>' + text.rep_analyzing + '</p>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'advaipbl_check_server_reputation',
                nonce: nonce
            },
            success: function (response) {
                loadingDiv.hide();
                btn.show().text(text.rep_check_again);

                if (response.success) {
                    const data = response.data;
                    const ip = data.ip;

                    if (data.status === 'clean') {
                        iconDiv.html('<span class="dashicons dashicons-yes-alt" style="color:green;"></span>');
                        const desc = text.rep_clean_desc.replace('%s', ip);
                        statusDiv.html('<h3 style="color:green; margin:0;">' + text.rep_clean_title + '</h3><p>' + desc + '</p>');
                    } else {
                        iconDiv.html('<span class="dashicons dashicons-warning" style="color:#d63638;"></span>');
                        const desc = text.rep_listed_desc.replace('%s', ip);
                        statusDiv.html('<h3 style="color:#d63638; margin:0;">' + text.rep_listed_title + '</h3><p>' + desc + '</p>');
                    }

                    let rows = '';
                    $.each(data.checks, function (key, info) {
                        let statusHtml = '';
                        let rowStyle = '';

                        // Mapeo de estados a textos traducidos (estos vienen del PHP ya traducidos en 'status_label' si lo hiciéramos así, pero para simplificar JS usamos lógica aquí con textos localizados)
                        // Mejor opción: El PHP ya envía info.status como código, traducimos aquí

                        if (info.status === 'clean') {
                            statusHtml = '<span style="color:green;">' + text.status_clean + '</span>';
                        } else if (info.status === 'listed') {
                            statusHtml = '<span style="color:red; font-weight:bold;">' + text.status_blacklisted + '</span>';
                            rowStyle = 'background-color: #fff5f5;';
                        } else if (info.status === 'skipped') {
                            statusHtml = '<span style="color:#999;">' + text.status_skipped + '</span>';
                        } else if (info.status === 'warning') {
                            statusHtml = '<span style="color:#f59e0b;">' + text.status_warning + '</span>';
                        } else {
                            statusHtml = '<span style="color:#999;">' + text.status_unknown + '</span>';
                        }

                        rows += `<tr style="${rowStyle}">
                            <td><strong>${info.label}</strong></td>
                            <td>${statusHtml}</td>
                            <td>${info.detail || '-'}</td>
                        </tr>`;
                    });
                    resultsDiv.find('tbody').html(rows);
                    resultsDiv.show();

                } else {
                    statusDiv.html('<p style="color:red;">Error: ' + response.data.message + '</p>');
                }
            },
            error: function () {
                loadingDiv.hide();
                btn.show();
                statusDiv.html('<p style="color:red;">' + text.rep_error + '</p>');
            }
        });
    });

    // ========================================================================
    // INICIALIZACIÓN PRINCIPAL
    // ========================================================================

    initMapViewModal();
    initBulkActions();
    initWhitelistBulkActions();
    initBlockedIpsFilters();
    initAdminMenuCounter();
    attachGeoblockWarning();
    attachWhitelistRemoveWarning();
    initWhitelistAjaxButton();
    initConnectionTest();
    initMobileNav();
    initConfirmActions();
    //initGeolocationProviderLogic(); 
    initExportLogic();
    initPerPageSelector();
    initSettingsSearch();
    initApiVerification();
    initFloatingSaveBar();
    initLogFilterSelector();
    initClearLogModal();
    initTelemetryNotice();
    initIpTrustLogActions();
    initBlockedSignaturesActions();
    initTwoFactorAuthProfile();
    initTwoFactorUserTableForm();
    initGeolocationOptionsToggle();
    initGeoIpDownloader();
    initSettingsSideNav();
    initEndpointLockdownActions();
    initCountrySelectors();
    toggleRecaptchaV3Options();
    $('#advaipbl_recaptcha_version').on('change', toggleRecaptchaV3Options);

    // Nueva inicialización para el motor de reglas
    // Nueva inicialización para el motor de reglas
    initializeAdvancedRules();

    // Generic Confirmation Modal Helper
    window.advaipbl_show_confirm_modal = function (title, message, onConfirm) {
        const modal = $('#advaipbl-general-confirm-modal');
        const titleEl = modal.find('#advaipbl-confirm-title');
        const messageEl = modal.find('#advaipbl-confirm-message');
        const confirmBtn = modal.find('#advaipbl-confirm-action-btn');
        const cancelBtn = modal.find('.advaipbl-modal-cancel');

        titleEl.text(title);
        messageEl.html(message); // Allow HTML in message

        // Remove previous event listeners to prevent duplicates
        confirmBtn.off('click');
        cancelBtn.off('click');

        confirmBtn.on('click', function () {
            modal.hide();
            if (typeof onConfirm === 'function') {
                onConfirm();
            }
        });

        cancelBtn.on('click', function () {
            modal.hide();
        });

        modal.show();
    };

    initAuditLogActions();

    function initAuditLogActions() {
        const clearBtn = $('#advaipbl-clear-audit-log-btn');
        const modal = $('#advaipbl-clear-log-modal');
        const confirmBtn = $('#advaipbl-confirm-clear-log');
        const cancelBtn = modal.find('.advaipbl-modal-cancel');
        const startScanBtn = $('#advaipbl-manual-fim-scan-btn'); // FIM Button

        if (clearBtn.length) {
            clearBtn.on('click', function (e) {
                e.preventDefault();
                // Use generic modal instead of custom one if desired, or keep specific logic.
                // The user requested standardizing, so let's use the new helper if appropriate.
                // However, the existing 'advaipbl-clear-log-modal' might differ. 
                // Let's inspect the previous code: it showed a specific modal #advaipbl-clear-log-modal.
                // If we want to replace it purely with the generic one:

                advaipbl_show_confirm_modal(
                    advaipbl_admin_data.text.confirm_clear_log_title || 'Clear Audit Log',
                    advaipbl_admin_data.text.confirm_clear_log || 'Are you sure you want to clear the audit log?',
                    function () {
                        performClearLog(clearBtn);
                    }
                );
            });
        }

        // Helper for clearing log
        function performClearLog(btn) {
            const originalText = btn.text();
            btn.prop('disabled', true).text(advaipbl_admin_data.text.processing || 'Processing...');

            $.post(ajaxurl, {
                action: 'advaipbl_clear_audit_log',
                nonce: advaipbl_admin_data.nonces.clear_log_nonce
            }).done(function (response) {
                if (response.success) {
                    location.reload();
                } else {
                    var msg = 'Error clearing logs.';
                    if (response && response.data && response.data.message) {
                        msg = response.data.message;
                    }
                    alert(msg);
                    btn.prop('disabled', false).text(originalText);
                }
            }).fail(function () {
                alert(advaipbl_admin_data.text.ajax_error || 'AJAX Error');
                btn.prop('disabled', false).text(originalText);
            });
        }




        // FIM Manual Scan Button Logic
        if (startScanBtn.length) {
            startScanBtn.on('click', function (e) {
                e.preventDefault();
                const btn = $(this);
                const statusSpan = $('#advaipbl-fim-scan-status');
                const nonce = btn.data('nonce');

                if (btn.prop('disabled')) return;

                advaipbl_show_confirm_modal(
                    advaipbl_admin_data.text.confirm_scan_title || 'Run FIM Scan',
                    advaipbl_admin_data.text.confirm_scan || 'Run FIM scan now?',
                    function () {
                        btn.prop('disabled', true);
                        statusSpan.css('color', '').text(advaipbl_admin_data.text.processing || 'Scanning...');

                        $.post(ajaxurl, {
                            action: 'advaipbl_run_fim_scan',
                            nonce: nonce
                        }).done(function (response) {
                            if (response.success) {
                                statusSpan.css('color', 'green').text(response.data.message);
                                setTimeout(() => { location.reload(); }, 2000);
                            } else {
                                statusSpan.css('color', 'red').text(response.data.message);
                                btn.prop('disabled', false);
                            }
                        }).fail(function () {
                            statusSpan.css('color', 'red').text(advaipbl_admin_data.text.ajax_error || 'AJAX Error');
                            btn.prop('disabled', false);
                        });
                    }
                );
            });
        }
    }
});