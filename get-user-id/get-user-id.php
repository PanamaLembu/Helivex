<?php
/**
 * Plugin Name: Get User ID
 * Description: A temporary plugin to get a user's ID.
 * Version: 1.0
 * Author: Gemini
 */

function get_user_id_admin_notice() {
    $user = get_user_by('email', 'bibbesq@yahoo.com');
    if ($user) {
        ?>
        <div class="notice notice-success is-dismissible">
            <p><?php echo 'The user ID for bibbesq@yahoo.com is: ' . $user->ID; ?></p>
        </div>
        <?php
    } else {
        ?>
        <div class="notice notice-error is-dismissible">
            <p><?php echo 'User not found.'; ?></p>
        </div>
        <?php
    }
}
add_action('admin_notices', 'get_user_id_admin_notice');
