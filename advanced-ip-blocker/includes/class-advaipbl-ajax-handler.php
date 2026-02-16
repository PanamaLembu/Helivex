<?php

if ( ! defined( 'ABSPATH' ) ) exit;

class ADVAIPBL_Ajax_Handler {

    /**
     * Instancia de la clase principal del plugin.
     * @var ADVAIPBL_Main
     */
    private $plugin;

    /**
 * Constructor.
 * @param ADVAIPBL_Main $plugin_instance La instancia de la clase principal.
 */
    public function __construct(ADVAIPBL_Main $plugin_instance) {
    $this->plugin = $plugin_instance;
}

    public function ajax_get_dashboard_stats() {
        // 1. Verificamos el nonce. El primer argumento debe coincidir con la acción del nonce que creamos.
        check_ajax_referer('wp_ajax_advaipbl_get_dashboard_stats', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }
        $stats = $this->plugin->dashboard_manager->get_dashboard_stats();
        if ($stats) {
            wp_send_json_success($stats);
        } else {
            wp_send_json_error(['message' => 'Could not retrieve stats.']);
        }
    }
	/**
     * AJAX callback para resetear la puntuación de amenaza de una IP.
     */
        public function ajax_reset_threat_score() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_reset_score_nonce', 'nonce');

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (!$ip) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'advanced-ip-blocker')]);
        }

        $success = $this->plugin->threat_score_manager->reset_score($ip);

        $this->plugin->desbloquear_ip($ip);

        if ($success) {
			/* translators: %1$s: IP, %2$s: Username. */
            $this->plugin->log_event(sprintf(__('Threat score for IP %1$s was manually reset by %2$s.', 'advanced-ip-blocker'), $ip, $this->plugin->get_current_admin_username()), 'info');
            wp_send_json_success(['message' => __('Score reset and IP unblocked successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to reset score.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback para añadir una firma a la lista blanca y eliminarla de la lista de bloqueo.
     */
    public function ajax_whitelist_signature() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_whitelist_signature_nonce', 'nonce');

        $hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        if (strlen($hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash.', 'advanced-ip-blocker')]);
        }

        // 1. Obtenemos los detalles de la firma para construir los comentarios.
        $details = $this->plugin->fingerprint_manager->get_signature_details($hash);
        if ($details === false) {
            wp_send_json_error(['message' => __('Could not retrieve signature details to create whitelist entry.', 'advanced-ip-blocker')]);
        }
        
        // 2. Construimos la entrada para la lista blanca con comentarios.
        $entry_lines = ["\n# Signature Components:"];
        $entry_lines[] = "# User-Agent: " . ($details['sample_user_agent'] ?? 'N/A');
        if (!empty($details['sample_headers'])) {
            foreach ($details['sample_headers'] as $key => $value) {
                $entry_lines[] = "# " . $key . ": " . $value;
            }
        }
        $entry_lines[] = $hash;
        $entry_to_add = implode("\n", $entry_lines);
        
        // 3. Obtenemos el array COMPLETO de settings, modificamos la clave y guardamos.
        $options = get_option(ADVAIPBL_Main::OPTION_SETTINGS, []);
        $current_whitelist = $options['trusted_signature_hashes'] ?? '';
        $new_whitelist = $current_whitelist . "\n" . $entry_to_add;
        
        // Actualizamos la clave dentro del array de opciones.
        $options['trusted_signature_hashes'] = trim($new_whitelist);
        
        // Guardamos el array de opciones completo.
        update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);

        // 4. Eliminamos la firma de la lista de maliciosos.
        $this->plugin->fingerprint_manager->delete_signature($hash);
        /* translators: %s: hash, %s: Username. */
        $this->plugin->log_event(sprintf(__('Signature %1$s... whitelisted by %2$s.', 'advanced-ip-blocker'), substr($hash, 0, 12), $this->plugin->get_current_admin_username()), 'info');
        wp_send_json_success(['message' => __('Signature whitelisted successfully.', 'advanced-ip-blocker')]);
    }
	/**
     * AJAX callback para eliminar una firma maliciosa.
     */
    public function ajax_delete_signature() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_delete_signature_nonce', 'nonce');

        $signature_hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        // Validamos que el hash tenga la longitud correcta de un sha256.
        if (strlen($signature_hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash format.', 'advanced-ip-blocker')]);
        }       
        $success = $this->plugin->fingerprint_manager->delete_signature($signature_hash);

        if ($success) {
			/* translators: %1$s: Hash, %2$s: Username */
            $this->plugin->log_event(sprintf(__('Malicious signature %1$s... was manually deleted by %2$s.', 'advanced-ip-blocker'), substr($signature_hash, 0, 12), $this->plugin->get_current_admin_username()), 'warning');
            wp_send_json_success(['message' => __('Signature deleted successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to delete signature. It might have already expired or been removed.', 'advanced-ip-blocker')]);
        }
    }
	
	    /**
     * AJAX callback para obtener los detalles de una firma maliciosa.
     */
    public function ajax_get_signature_details() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_signature_details_nonce', 'nonce');

        $signature_hash = isset($_POST['hash']) ? sanitize_text_field(wp_unslash($_POST['hash'])) : '';
        if (strlen($signature_hash) !== 64) {
            wp_send_json_error(['message' => __('Invalid signature hash format.', 'advanced-ip-blocker')]);
        }
        
        $details = $this->plugin->fingerprint_manager->get_signature_details($signature_hash);

        if ($details !== false) {
            wp_send_json_success(['details' => $details]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve signature details.', 'advanced-ip-blocker')]);
        }
    }
	
	    /**
     * AJAX callback para obtener los detalles de un Endpoint Lockdown.
     */
    public function ajax_get_lockdown_details() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_lockdown_details_nonce', 'nonce');

        $lockdown_id = isset($_POST['id']) ? absint($_POST['id']) : 0;
        if (!$lockdown_id) {
            wp_send_json_error(['message' => __('Invalid Lockdown ID.', 'advanced-ip-blocker')]);
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'advaipbl_endpoint_lockdowns';
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $lockdown = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_name} WHERE id = %d", $lockdown_id), ARRAY_A);

        if ($lockdown) {
            wp_send_json_success(['details' => $lockdown]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve lockdown details.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback para obtener el historial de eventos de una IP.
     */
    public function ajax_get_score_history() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_get_history_nonce', 'nonce');

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        if (!$ip) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'advanced-ip-blocker')]);
        }        
        $history = $this->plugin->threat_score_manager->get_log_details($ip);

        if ($history !== false) {
            wp_send_json_success(['history' => $history]);
        } else {
            wp_send_json_error(['message' => __('Could not retrieve history.', 'advanced-ip-blocker')]);
        }
    }
	/**
     * AJAX callback to test the server's outbound connection.
     */
    public function ajax_test_outbound_connection() {
        if ( ! current_user_can('manage_options') ) {
            wp_send_json_error( [ 'message' => 'Permission denied.' ] );
        }
        check_ajax_referer( 'advaipbl_test_connection_nonce', 'nonce' );

        $response = wp_remote_get('https://api.ipify.org?format=json', [ 'timeout' => 10 ]);

        if ( is_wp_error($response) ) {
            wp_send_json_error( [ 'message' => 'Error: ' . $response->get_error_message() ] );
        }

        $http_code = wp_remote_retrieve_response_code( $response );
        if ( $http_code !== 200 ) {
            wp_send_json_error( [ 'message' => sprintf( 'Error: Received HTTP status code %d.', $http_code ) ] );
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( isset( $body['ip'] ) && filter_var( $body['ip'], FILTER_VALIDATE_IP ) ) {
            wp_send_json_success( [ 'message' => sprintf( 'Success! Connection established from IP: %s', $body['ip'] ) ] );
        }

        wp_send_json_error( [ 'message' => 'Error: The response from the test service was invalid.' ] );
    }
	/**
     * AJAX callback to add a specific IP to the whitelist.
     * This is used by the interactive buttons in the admin interface.
     */

    public function ajax_add_ip_to_whitelist() {
    // 1. Validar permisos y nonce de seguridad (esto no cambia).
    if ( ! current_user_can('manage_options') ) {
        wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
    }
    check_ajax_referer( 'advaipbl_add_whitelist_nonce', 'nonce' );

    // 2. Obtener y validar la IP del POST. Esta función AJAX solo maneja IPs individuales.
    if ( ! isset( $_POST['ip'] ) || ! filter_var( wp_unslash( $_POST['ip'] ), FILTER_VALIDATE_IP ) ) {
        wp_send_json_error( [ 'message' => __( 'Invalid or missing IP address.', 'advanced-ip-blocker' ) ] );
    }
    $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ) );
    
    $detail = isset( $_POST['detail'] ) ? sanitize_text_field( wp_unslash( $_POST['detail'] ) ) : __('Added via admin action', 'advanced-ip-blocker');

    // 3. Reutilizar nuestra nueva lógica centralizada.
    $success = $this->plugin->add_to_whitelist_and_unblock( $ip, $detail );

    if ( $success ) {
        /* translators: %s: The IP address that was successfully whitelisted. */
        wp_send_json_success( [ 'message' => sprintf( __( '%s successfully added to the whitelist.', 'advanced-ip-blocker' ), $ip ) ] );
    } else {
        /* translators: %s: The IP address that is already whitelisted. */
        wp_send_json_success( [ 'message' => sprintf( __( '%s is already whitelisted.', 'advanced-ip-blocker' ), $ip ) ] );
    }
}
    /**
    * AJAX callback para verificar una API key de geolocalización o de Cloudflare.
    */
    public function ajax_verify_api_key() {
        if ( ! current_user_can('manage_options') ) {
            wp_send_json_error( ['message' => __('Permission denied.', 'advanced-ip-blocker')] );
        }
        check_ajax_referer( 'advaipbl_verify_api_nonce', 'nonce' );

        $provider = isset($_POST['provider']) ? sanitize_text_field(wp_unslash($_POST['provider'])) : '';
        $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';

        if (empty($provider)) {
            wp_send_json_error( ['message' => __('Provider is missing.', 'advanced-ip-blocker')] );
        }
        
        if ($provider === 'cloudflare') {
            if (empty($api_key)) {
                wp_send_json_error(['message' => __('API Token is missing.', 'advanced-ip-blocker')]);
            }
            
            // Llamamos al Cloudflare Manager
            $result = $this->plugin->cloudflare_manager->verify_token($api_key);
            
            if (is_wp_error($result)) {
                wp_send_json_error(['message' => $result->get_error_message()]);
            } else {
                wp_send_json_success(['message' => __('Token verified successfully! (Status: Active)', 'advanced-ip-blocker')]);
            }
            return; // Terminamos aquí para Cloudflare
        }

        // --- Lógica existente para Geolocalización ---
        $this->plugin->geolocation_manager->set_transient_api_key($provider, $api_key);
        $result = $this->plugin->geolocation_manager->fetch_location('8.8.8.8');
        $this->plugin->geolocation_manager->clear_transient_api_key($provider);

        if ( $result && !isset($result['error']) ) {
            wp_send_json_success(['message' => __('API Key is valid!', 'advanced-ip-blocker')]);
        } else {
            $error_message = $result['error_message'] ?? __('Invalid API Key or connection error.', 'advanced-ip-blocker');
            wp_send_json_error(['message' => $error_message]);
        }
    } 
    /**
     * Callback de AJAX para gestionar la respuesta al aviso de telemetría.
     */
    public function ajax_handle_telemetry_notice() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error();
        }
        check_ajax_referer('advaipbl_telemetry_nonce', 'nonce');

        $action = isset($_POST['telemetry_action']) ? sanitize_key($_POST['telemetry_action']) : '';

        if ('allow' === $action) {
            // Obtenemos las opciones a través de la instancia del plugin.
            $options = $this->plugin->options;
            $options['allow_telemetry'] = '1';

            update_option(ADVAIPBL_Main::OPTION_SETTINGS, $options);
            update_option('advaipbl_telemetry_notice_dismissed', '1');

            if (!wp_next_scheduled('advaipbl_send_telemetry_data_event')) {
                wp_schedule_event(time() + DAY_IN_SECONDS, 'weekly', 'advaipbl_send_telemetry_data_event');

                $this->plugin->log_event('Telemetry cron job scheduled after user consent.', 'info');
            }

            wp_send_json_success();

        } elseif ('dismiss' === $action) {
            update_option('advaipbl_telemetry_notice_dismissed', '1');
            wp_clear_scheduled_hook('advaipbl_send_telemetry_data_event');
            
            wp_send_json_success();
        }

        wp_send_json_error();
    }
	/**
     * AJAX callback para generar un nuevo secreto 2FA para un usuario.
     */
    public function ajax_2fa_generate() {
        check_ajax_referer( 'advaipbl_2fa_generate_nonce', 'nonce' );
        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $user = get_user_by( 'id', $user_id );
        if ( ! $user ) {
            wp_send_json_error( [ 'message' => __( 'Invalid user.', 'advanced-ip-blocker' ) ] );
        }
        $data = $this->plugin->tfa_manager->generate_new_secret_for_user( $user );
        wp_send_json_success( $data );
    }

    /**
     * AJAX callback para verificar y activar 2FA para un usuario.
     */
    public function ajax_2fa_activate() {
        check_ajax_referer( 'advaipbl_2fa_activate_nonce', 'nonce' );
        $user_id      = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        $code         = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
        $backup_codes = isset( $_POST['backup_codes'] ) && is_array( $_POST['backup_codes'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['backup_codes'] ) ) : [];

        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $success = $this->plugin->tfa_manager->verify_and_activate( $user_id, $code, $backup_codes );
        if ( $success ) {
            wp_send_json_success();
        } else {
            wp_send_json_error( [ 'message' => __( 'Invalid verification code. Please try again.', 'advanced-ip-blocker' ) ] );
        }
    }

    /**
     * AJAX callback para desactivar 2FA para un usuario.
     */
        public function ajax_2fa_deactivate() {
        check_ajax_referer( 'advaipbl_2fa_deactivate_nonce', 'nonce' );
        $user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
        if ( ! $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Permission denied.', 'advanced-ip-blocker' ) ] );
        }
        $this->plugin->tfa_manager->deactivate_for_user( $user_id );
        wp_send_json_success();
    }
	/**
     * AJAX callback para iniciar la descarga de la base de datos GeoIP.
     */
    public function ajax_update_geoip_db() {
        if ( ! isset( $_POST['nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'advaipbl_update_geoip_nonce' ) ) {
            wp_send_json_error( ['message' => 'Nonce verification failed.'], 403 );
        }
        if ( ! current_user_can( 'manage_options' ) || ! $this->plugin->geoip_manager ) {
            wp_send_json_error( ['message' => 'Permission denied or module not available.'], 403 );
        }
        
        // Aumentamos el límite de tiempo de ejecución para la descarga
        // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        set_time_limit(300);

        $result = $this->plugin->geoip_manager->download_and_unpack_databases();
        
        if ( $result['success'] ) {
            wp_send_json_success( ['message' => $result['message']] );
        } else {
            wp_send_json_error( ['message' => $result['message']] );
        }
    }

   /**
 * AJAX callback para obtener las reglas avanzadas, con soporte para paginación.
 */
public function ajax_get_advanced_rules() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_get_rules_nonce', 'nonce');
    if (ob_get_level()) {
        ob_clean();
    }
    
    // Support fetching a single rule for editing
    if (isset($_POST['rule_id'])) {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash
        $rule_id = sanitize_text_field($_POST['rule_id']);
        $all_rules = $this->plugin->rules_engine->get_rules();
        $found_rule = null;
        foreach ($all_rules as $r) {
            if (isset($r['id']) && $r['id'] === $rule_id) {
                $found_rule = $r;
                break;
            }
        }
        
        if ($found_rule) {
             wp_send_json_success(['rules' => [$found_rule]]);
        } else {
             wp_send_json_error(['message' => __('Rule not found.', 'advanced-ip-blocker')]);
        }
    }

    $page = isset($_POST['page']) ? absint($_POST['page']) : 1;
    $per_page = 20;
    $all_rules = $this->plugin->rules_engine->get_rules();
    // REMOVED REVERSE: We want to display rules in priority order (index 0 first).
    $all_rules = is_array($all_rules) ? $all_rules : [];
    $total_items = count($all_rules);
    $total_pages = ceil($total_items / $per_page);
    $rules_for_page = array_slice($all_rules, ($page - 1) * $per_page, $per_page);
    wp_send_json_success([
        'rules'       => $rules_for_page,
        'pagination'  => [
            'total_items' => $total_items,
            'total_pages' => $total_pages,
            'current_page'=> $page,
        ]
    ]);
    wp_die();
}

    /**
     * AJAX callback para guardar (crear o actualizar) una regla avanzada.
     */
    public function ajax_save_advanced_rule() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_save_rule_nonce', 'nonce');

        // Decode JSON directly after unslashing. We do NOT use sanitize_text_field here as it breaks JSON structure
        // and stripslashes breaks escaped characters within the JSON strings (e.g., regex backslashes).
        // Individual fields are sanitized later in Rules_Engine::sanitize_rule().
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $rule_data = isset($_POST['rule']) ? json_decode(wp_unslash($_POST['rule']), true) : null;
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($rule_data)) {
            wp_send_json_error(['message' => __('Invalid rule data received.', 'advanced-ip-blocker')]);
        }

        // Aquí deberíamos añadir una sanitización profunda, pero por ahora confiamos en la entrada
        $rule_id = $rule_data['id'] ?? null;

        if (empty($rule_id)) { // Es una nueva regla
            $saved_rule = $this->plugin->rules_engine->add_rule($rule_data);
            if ($saved_rule) {
                wp_send_json_success(['message' => __('Rule created successfully.', 'advanced-ip-blocker'), 'rule' => $saved_rule]);
            } else {
                wp_send_json_error(['message' => __('Failed to create rule.', 'advanced-ip-blocker')]);
            }
        } else { // Es una actualización
            if ($this->plugin->rules_engine->update_rule($rule_id, $rule_data)) {
                wp_send_json_success(['message' => __('Rule updated successfully.', 'advanced-ip-blocker'), 'rule' => $rule_data]);
            } else {
                wp_send_json_error(['message' => __('Failed to update rule. It may not exist.', 'advanced-ip-blocker')]);
            }
        }
    }

    /**
     * AJAX callback para eliminar una regla avanzada.
     */
    public function ajax_delete_advanced_rule() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_delete_rule_nonce', 'nonce');

        $rule_id = isset($_POST['rule_id']) ? sanitize_text_field(wp_unslash($_POST['rule_id'])) : null;
        if (empty($rule_id)) {
            wp_send_json_error(['message' => __('Invalid rule ID.', 'advanced-ip-blocker')]);
        }

        if ($this->plugin->rules_engine->delete_rule($rule_id)) {
            wp_send_json_success(['message' => __('Rule deleted successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to delete rule. It may have already been deleted.', 'advanced-ip-blocker')]);
        }
    }
	
	/**
 * AJAX callback para eliminar reglas avanzadas en lote.
 */
public function ajax_bulk_delete_advanced_rules() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_bulk_delete_rules_nonce', 'nonce');

    $rule_ids = isset($_POST['rule_ids']) && is_array($_POST['rule_ids']) ? array_map('sanitize_text_field', wp_unslash($_POST['rule_ids']) ) : [];
    if (empty($rule_ids)) {
        wp_send_json_error(['message' => __('No rules selected.', 'advanced-ip-blocker')]);
        wp_die();
    }

    $deleted_count = 0;
    foreach ($rule_ids as $rule_id) {
        if ($this->plugin->rules_engine->delete_rule($rule_id)) {
            $deleted_count++;
        }
    }

    if ($deleted_count > 0) {
        /* translators: %d: Number of rules deleted. */
        $message = sprintf(_n('%d rule deleted successfully.', '%d rules deleted successfully.', $deleted_count, 'advanced-ip-blocker'), $deleted_count);
        wp_send_json_success(['message' => $message]);
    } else {
        wp_send_json_error(['message' => __('Failed to delete the selected rules.', 'advanced-ip-blocker')]);
    }
    wp_die();
}

/**
 * AJAX callback para verificar una clave API de AbuseIPDB.
 */
public function ajax_verify_abuseipdb_key() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        wp_die();
    }
    check_ajax_referer('advaipbl_verify_abuseipdb_nonce', 'nonce');

    $api_key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';
    
    // La lógica de verificación ya está en el manager, simplemente la llamamos.
    $result = $this->plugin->abuseipdb_manager->verify_api_key($api_key);

    if ($result['success']) {
        wp_send_json_success(['message' => $result['message']]);
    } else {
        wp_send_json_error(['message' => $result['message']]);
    }
    wp_die();
}

/**
     * AJAX callback para ejecutar el escaneo profundo de vulnerabilidades.
     */
    public function ajax_run_deep_scan() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_deep_scan_nonce', 'nonce');

        // Asegurar que el scanner está cargado
        if (!isset($this->plugin->site_scanner)) {
             require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
             $this->plugin->site_scanner = new ADVAIPBL_Site_Scanner($this->plugin);
        }

        $result = $this->plugin->site_scanner->check_vulnerabilities_via_api();

        if (isset($result['status']) && $result['status'] === 'error') {
            wp_send_json_error(['message' => __('API connection failed. Please try again later.', 'advanced-ip-blocker')]);
        }

        wp_send_json_success($result);
    }
	
	/**
     * AJAX callback para comprobar la reputación del servidor.
     */
    public function ajax_check_server_reputation() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }
        check_ajax_referer('advaipbl_reputation_nonce', 'nonce');

        if (!isset($this->plugin->site_scanner)) {
             require_once plugin_dir_path(__FILE__) . 'class-advaipbl-site-scanner.php';
             $this->plugin->site_scanner = new ADVAIPBL_Site_Scanner($this->plugin);
        }

        $result = $this->plugin->site_scanner->check_server_reputation();
        
        if (isset($result['status']) && $result['status'] === 'error') {
             wp_send_json_error(['message' => $result['message']]);
        }

        wp_send_json_success($result);
    }

    /**
     * Ajax handler to reorder advanced rules.
     */
    public function ajax_reorder_advanced_rules() {
        check_ajax_referer('advaipbl_reorder_rules_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        $rule_id = isset($_POST['rule_id']) ? sanitize_text_field(wp_unslash($_POST['rule_id'])) : '';
        $direction = isset($_POST['direction']) ? sanitize_text_field(wp_unslash($_POST['direction'])) : '';

        if (empty($rule_id) || !in_array($direction, ['up', 'down'], true)) {
            wp_send_json_error(['message' => __('Invalid parameters.', 'advanced-ip-blocker')]);
        }

        $rules = $this->plugin->rules_engine->get_rules();
        
        $rules = array_values($rules);
        
        $target_index = -1;

        // Find current index
        foreach ($rules as $index => $rule) {
            if (isset($rule['id']) && $rule['id'] === $rule_id) {
                $target_index = $index;
                break;
            }
        }

        if ($target_index === -1) {
            wp_send_json_error(['message' => __('Rule not found.', 'advanced-ip-blocker')]);
        }

        // Swap logic
        if ($direction === 'up') {
            if ($target_index > 0 && isset($rules[$target_index - 1])) {
                $temp = $rules[$target_index - 1];
                $rules[$target_index - 1] = $rules[$target_index];
                $rules[$target_index] = $temp;
            }
        } elseif ($direction === 'down') {
            if ($target_index < count($rules) - 1 && isset($rules[$target_index + 1])) {
                $temp = $rules[$target_index + 1];
                $rules[$target_index + 1] = $rules[$target_index];
                $rules[$target_index] = $temp;
            }
        }

        update_option(ADVAIPBL_Rules_Engine::OPTION_RULES, $rules);

        wp_send_json_success(['message' => __('Rule reordered successfully.', 'advanced-ip-blocker')]);
    }
    
    /**
     * AJAX action to clear audit logs.
     */
    public function ajax_clear_audit_logs() {
        check_ajax_referer('advaipbl_clear_audit_logs_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        if (!isset($this->plugin->audit_logger)) {
            wp_send_json_error(['message' => __('Audit Logger not active.', 'advanced-ip-blocker')]);
        }

        $result = $this->plugin->audit_logger->clear_all_logs();

        if ($result !== false) {
            /* translators: %s: Username. */
            $this->plugin->log_event(sprintf(__('Audit logs manually cleared by %s.', 'advanced-ip-blocker'), $this->plugin->get_current_admin_username()), 'warning');
            wp_send_json_success(['message' => __('Audit logs cleared successfully.', 'advanced-ip-blocker')]);
        } else {
            wp_send_json_error(['message' => __('Failed to clear logs.', 'advanced-ip-blocker')]);
        }
    }

    /**
     * AJAX Handler for manual FIM Scan.
     */


    public function ajax_run_fim_scan() {
        check_ajax_referer('advaipbl_run_fim_scan_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied.', 'advanced-ip-blocker')]);
        }

        if (empty($this->plugin->options['enable_fim'])) {
            wp_send_json_error(['message' => __('File Integrity Monitor is disabled.', 'advanced-ip-blocker')]);
        }

        if (!isset($this->plugin->file_verifier)) {
             wp_send_json_error(['message' => __('File Verifier module not loaded.', 'advanced-ip-blocker')]);
        }

        $changes = $this->plugin->file_verifier->scan_files();

        if (empty($changes)) {
            wp_send_json_success(['message' => __('Scan complete. No changes detected.', 'advanced-ip-blocker')]);
        } else {
            // Summary count
            $count = count($changes);
            /* translators: %d: Number of files changed. */
            $msg = sprintf(_n('Scan complete. %d file change detected (Alert sent).', 'Scan complete. %d file changes detected (Alert sent).', $count, 'advanced-ip-blocker'), $count);
            wp_send_json_success(['message' => $msg]);
        }
    }

}