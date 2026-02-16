<?php
/**
 * Plugin Name: Custom Admin Dashboard
 * Description: A custom admin dashboard for managing orders and inventory.
 * Version: 1.0
 * Author: Gemini
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// Add the admin menu page
add_action('admin_menu', 'cad_add_admin_menu');

function cad_add_admin_menu() {
    add_menu_page(
        'Admin Dashboard',
        'Admin Dashboard',
        'manage_options',
        'custom-admin-dashboard',
        'cad_render_admin_page',
        'dashicons-dashboard',
        2
    );
}

// Render the admin page
function cad_render_admin_page() {
    ?>
    <div class="wrap">
        <h1>Hello World! This is the custom admin dashboard.</h1>
    </div>
    <?php
}
