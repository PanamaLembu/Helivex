<?php
/**
 * Plugin Name: Helivex Dashboard
 * Description: A custom admin dashboard for managing orders and inventory.
 * Version: 1.0
 * Author: Gemini
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// Add the admin menu page
add_action('admin_menu', 'helivex_add_admin_menu');

function helivex_add_admin_menu() {
    add_menu_page(
        'Helivex Dashboard',
        'Helivex Dashboard',
        'manage_options',
        'helivex-dashboard',
        'helivex_render_admin_page',
        'dashicons-dashboard',
        2
    );
}

// Render the admin page
function helivex_render_admin_page() {
    ?>
    <div class="wrap">
        <h1>Welcome to the Helivex Dashboard!</h1>
    </div>
    <?php
}
