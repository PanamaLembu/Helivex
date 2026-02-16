<?php
/**
 * Plugin Name: Gemini Admin Dashboard
 * Description: A custom admin dashboard.
 * Version: 1.0
 * Author: Gemini
 */

add_action('admin_menu', function() {
    add_menu_page('Gemini Dashboard', 'Gemini Dashboard', 'manage_options', 'gemini-dashboard', function() {
        echo '<h1>Hello from the Gemini Dashboard!</h1>';
    }, 'dashicons-admin-generic', 2);
});
