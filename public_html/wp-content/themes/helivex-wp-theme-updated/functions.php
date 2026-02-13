<?php
/**
 * Helivex Labs functions and definitions
 */

if ( ! function_exists( 'helivex_setup' ) ) :
    function helivex_setup() {
        // Add support for WooCommerce
        add_theme_support( 'woocommerce' );
        add_theme_support( 'wc-product-gallery-zoom' );
        add_theme_support( 'wc-product-gallery-lightbox' );
        add_theme_support( 'wc-product-gallery-slider' );

        // Add default posts and comments RSS feed links to head.
        add_theme_support( 'automatic-feed-links' );

        // Let WordPress manage the document title.
        add_theme_support( 'title-tag' );

        // Enable support for Post Thumbnails on posts and pages.
        add_theme_support( 'post-thumbnails' );

        // Switch default core markup for search form, comment form, and comments to output valid HTML5.
        add_theme_support( 'html5', array(
            'search-form',
            'comment-form',
            'comment-list',
            'gallery',
            'caption',
            'style',
            'script',
        ) );
    }
endif;
add_action( 'after_setup_theme', 'helivex_setup' );

/**
 * Enqueue scripts and styles.
 */
function helivex_scripts() {
    // Main stylesheet
    wp_enqueue_style( 'helivex-style', get_stylesheet_uri(), array(), '1.0.0' );

    if ( is_singular() && comments_open() && get_option( 'thread_comments' ) ) {
        wp_enqueue_script( 'comment-reply' );
    }
}
add_action( 'wp_enqueue_scripts', 'helivex_scripts' );

/**
 * WooCommerce Customizations
 */
// Remove default WooCommerce styles if we want total control
// add_filter( 'woocommerce_enqueue_styles', '__return_empty_array' );

// Custom wrapper for WooCommerce content
function helivex_woocommerce_wrapper_before() {
    echo '<main id="primary" class="site-main min-h-screen bg-white">';
}
remove_action( 'woocommerce_before_main_content', 'woocommerce_output_content_wrapper', 10);
add_action( 'woocommerce_before_main_content', 'helivex_woocommerce_wrapper_before', 10);

function helivex_woocommerce_wrapper_after() {
    echo '</main>';
}
remove_action( 'woocommerce_after_main_content', 'woocommerce_output_content_wrapper_end', 10);
add_action( 'woocommerce_after_main_content', 'helivex_woocommerce_wrapper_after', 10);

// Remove WooCommerce Sidebar globally
remove_action( 'woocommerce_sidebar', 'woocommerce_get_sidebar', 10 );

// Unregister sidebars to prevent widgets from appearing
function helivex_remove_sidebars() {
    unregister_sidebar( 'sidebar-1' );
}
add_action( 'widgets_init', 'helivex_remove_sidebars', 11 );

/**
 * Add COA Meta Fields to Products
 */
function helivex_add_coa_fields() {
    woocommerce_wp_text_input(array(
        'id' => '_coa_batch',
        'label' => __('COA Batch ID', 'woocommerce'),
        'placeholder' => 'e.g. HXV-RET-2026-01',
        'desc_tip' => 'true',
        'description' => __('Enter the batch ID for the COA.', 'woocommerce'),
    ));
    woocommerce_wp_text_input(array(
        'id' => '_coa_purity',
        'label' => __('COA Purity', 'woocommerce'),
        'placeholder' => 'e.g. 99.8%',
        'desc_tip' => 'true',
        'description' => __('Enter the purity percentage.', 'woocommerce'),
    ));
    woocommerce_wp_text_input(array(
        'id' => '_coa_mass',
        'label' => __('COA Mass', 'woocommerce'),
        'placeholder' => 'e.g. 5162.34 g/mol',
        'desc_tip' => 'true',
        'description' => __('Enter the molecular mass.', 'woocommerce'),
    ));
    woocommerce_wp_text_input(array(
        'id' => '_coa_date',
        'label' => __('COA Date', 'woocommerce'),
        'placeholder' => 'e.g. JAN 15, 2026',
        'desc_tip' => 'true',
        'description' => __('Enter the test date.', 'woocommerce'),
    ));

    // Add Research-Specific Compliance Fields
    echo '<div class="options_group">';
    woocommerce_wp_text_input(array(
        'id' => '_research_cas',
        'label' => __('CAS Number', 'woocommerce'),
        'placeholder' => 'e.g. 2023788-19-2',
        'description' => __('Chemical Abstracts Service Registry Number.', 'woocommerce'),
    ));
    woocommerce_wp_text_input(array(
        'id' => '_research_formula',
        'label' => __('Molecular Formula', 'woocommerce'),
        'placeholder' => 'e.g. C189H284N54O50S',
        'description' => __('Chemical formula for research identification.', 'woocommerce'),
    ));
    echo '</div>';
    
    // Add COA Image Upload
    echo '<div class="options_group">';
    woocommerce_wp_text_input(array(
        'id' => '_coa_image',
        'label' => __('COA Image/PDF URL', 'woocommerce'),
        'placeholder' => 'Click the button to upload',
        'desc_tip' => 'true',
        'description' => __('Upload the Certificate of Analysis image or PDF.', 'woocommerce'),
    ));
    echo '<button type="button" class="button helivex-upload-button" data-target="_coa_image">' . __('Upload COA', 'helivex') . '</button>';
    echo '</div>';
}
add_action('woocommerce_product_options_general_product_data', 'helivex_add_coa_fields');

function helivex_save_coa_fields($post_id) {
    $fields = ['_coa_batch', '_coa_purity', '_coa_mass', '_coa_date', '_coa_image', '_research_cas', '_research_formula'];
    foreach ($fields as $field) {
        if (isset($_POST[$field])) {
            update_post_meta($post_id, $field, esc_attr($_POST[$field]));
        }
    }
}
add_action('woocommerce_process_product_meta', 'helivex_save_coa_fields');

/**
 * Enqueue Media Uploader for COA fields
 */
function helivex_admin_scripts($hook) {
    if ('post.php' != $hook && 'post-new.php' != $hook) return;
    wp_enqueue_media();
    ?>
    <script>
    jQuery(document).ready(function($){
        $('.helivex-upload-button').click(function(e) {
            e.preventDefault();
            var target = $(this).data('target');
            var custom_uploader = wp.media({
                title: 'Upload COA',
                button: { text: 'Use this file' },
                multiple: false
            }).on('select', function() {
                var attachment = custom_uploader.state().get('selection').first().toJSON();
                $('#' + target).val(attachment.url);
            }).open();
        });
    });
    </script>
    <?php
}
add_action('admin_enqueue_scripts', 'helivex_admin_scripts');

/**
 * Save Vial Dot Positions via AJAX
 */
function helivex_save_vial_dots() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $positions = $_POST['positions'];
    if (isset($positions) && is_array($positions)) {
        update_option('helivex_vial_dot_positions', $positions);
        wp_send_json_success('Positions saved');
    } else {
        wp_send_json_error('Invalid data');
    }
}
add_action('wp_ajax_save_vial_dots', 'helivex_save_vial_dots');

/**
 * Admin Image Replacement Feature
 */
function helivex_replace_image() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    if (!isset($_FILES['image'])) {
        wp_send_json_error('Missing data');
    }

    $file = $_FILES['image'];

    // Handle Product Image Replacement
    if (isset($_POST['product_id'])) {
        $product_id = intval($_POST['product_id']);
        
        // Use WordPress media functions to handle the upload
        require_once(ABSPATH . 'wp-admin/includes/image.php');
        require_once(ABSPATH . 'wp-admin/includes/file.php');
        require_once(ABSPATH . 'wp-admin/includes/media.php');

        $attachment_id = media_handle_upload('image', $product_id);

        if (is_wp_error($attachment_id)) {
            wp_send_json_error($attachment_id->get_error_message());
        }

        // Set the new attachment as the product's featured image
        update_post_meta($product_id, '_thumbnail_id', $attachment_id);
        
        wp_send_json_success([
            'message' => 'Product image updated successfully',
            'new_url' => wp_get_attachment_url($attachment_id)
        ]);
    }

    // Handle Theme Asset Replacement (Existing Logic)
    if (isset($_POST['target_path'])) {
        $target_relative_path = sanitize_text_field($_POST['target_path']); // e.g., "assets/images/vial.png"
        
        // Strip any remaining query strings or accidental parameters
        $target_relative_path = explode('?', $target_relative_path)[0];

        // Ensure the target path is within the theme's assets/images directory for security
        if (strpos($target_relative_path, 'assets/images/') !== 0) {
            wp_send_json_error('Invalid target path: ' . $target_relative_path);
        }

        $theme_dir = get_template_directory();
        $target_full_path = $theme_dir . '/' . $target_relative_path;

        // Check if directory exists, if not create it (though it should exist)
        $dir = dirname($target_full_path);
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }

        // Move the uploaded file to the target location, overwriting the existing file
        if (move_uploaded_file($file['tmp_name'], $target_full_path)) {
            wp_send_json_success('Theme image replaced successfully');
        } else {
            wp_send_json_error('Failed to save file');
        }
    }

    wp_send_json_error('Missing target info');
}
add_action('wp_ajax_helivex_replace_image', 'helivex_replace_image');

/**
 * Create the 10-Vial Research Kit Product
 */
function helivex_create_research_kit_product() {
    if (!isset($_GET['helivex_create_kit']) || $_GET['helivex_create_kit'] !== '1') {
        return;
    }

    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    $sku = 'HXV-10-VIAL-KIT';
    $existing_id = wc_get_product_id_by_sku($sku);
    
    if ($existing_id) {
        $product = wc_get_product($existing_id);
    } else {
        $product = new WC_Product_Variable();
        $product->set_sku($sku);
    }

    $product->set_name('10-Vial Research Kit (Custom Selection)');
    $product->set_description('Our flagship 10-vial research kit. Select your preferred peptide below. Each kit contains 10 vacuum-sealed vials of your chosen compound, lyophilized for maximum stability.');
    $product->set_short_description('The ultimate laboratory standard. Choose your compound and receive a bulk-discounted 10-vial kit for extended research protocols.');
    $product->set_status('publish');
    $product->set_category_ids([get_term_by('name', 'Peptides', 'product_cat')->term_id]);

    // RUO Compliance: Add mandatory disclaimer to all products
    $product->set_short_description($product->get_short_description() . '<br><br><strong style="color:#ef4444;">WARNING: FOR RESEARCH USE ONLY. NOT FOR HUMAN OR VETERINARY USE.</strong>');

    // Define the Peptides for the kit
    $peptides = [
        'RT 5mg',
        'TRZ 10mg',
        'SM 5mg',
        'Cagrilintide 5mg',
        'BPC-157 5mg',
        'TB-500 5mg',
        'AOD-9604 5mg',
        'Ipamorelin 5mg',
        'MT-2 10mg'
    ];

    // Create Attribute
    $attribute = new WC_Product_Attribute();
    $attribute->set_id(0);
    $attribute->set_name('Peptide Selection');
    $attribute->set_options($peptides);
    $attribute->set_position(0);
    $attribute->set_visible(true);
    $attribute->set_variation(true);
    $product->set_attributes([$attribute]);

    $product_id = $product->save();

    // Create Variations
    foreach ($peptides as $peptide) {
        $v_sku = $sku . '-' . sanitize_title($peptide);
        $v_id = wc_get_product_id_by_sku($v_sku);
        
        if ($v_id) {
            $variation = wc_get_product($v_id);
        } else {
            $variation = new WC_Product_Variation();
            $variation->set_parent_id($product_id);
            $variation->set_sku($v_sku);
        }

        $variation->set_attributes(['peptide-selection' => $peptide]);
        $variation->set_regular_price('299.00'); // Standard kit price
        $variation->set_status('publish');
        $variation->set_manage_stock(false);
        $variation->set_stock_status('instock');
        $variation->save();
    }

    // Set Image (using the red vial)
    if (function_exists('helivex_set_product_image_from_url')) {
        helivex_set_product_image_from_url($product_id, 'helivex-vial-red.png');
    }

    echo "Research Kit Product Created/Updated successfully! Product ID: $product_id";
    exit;
}
add_action('admin_init', 'helivex_create_research_kit_product');

/**
 * Security Hardening & Compliance
 */

// 1. Enforce Security Headers
function helivex_security_headers() {
    if (!is_admin()) {
        header("Content-Security-Policy: default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; font-src 'self' data: https:; upgrade-insecure-requests;");
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: SAMEORIGIN");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
    }
}
add_action('send_headers', 'helivex_security_headers');

// 2. RUO Disclaimer at Checkout
add_action('woocommerce_review_order_before_submit', 'helivex_ruo_checkout_checkbox', 10);
function helivex_ruo_checkout_checkbox() {
    woocommerce_form_field('ruo_agreement', array(
        'type'          => 'checkbox',
        'class'         => array('form-row-wide'),
        'label_class'   => array('woocommerce-form__label woocommerce-form__label-for-checkbox checkbox'),
        'input_class'   => array('woocommerce-form__input woocommerce-form__input-checkbox input-checkbox'),
        'required'      => true,
        'label'         => 'I acknowledge that these products are <strong>FOR RESEARCH USE ONLY</strong> and not for human consumption. I agree to the <a href="/terms-of-service" target="_blank">Terms of Service</a>.',
    ));
}

// Validate RUO Checkbox
add_action('woocommerce_checkout_process', 'helivex_ruo_checkout_validation');
function helivex_ruo_checkout_validation() {
    if (!isset($_POST['ruo_agreement']) || empty($_POST['ruo_agreement'])) {
        wc_add_notice('You must acknowledge the Research Use Only (RUO) disclaimer to proceed.', 'error');
    }
}

// 3. Age Verification Hook (18+)
function helivex_age_verification_modal() {
    if (isset($_COOKIE['helivex_age_verified'])) return;
    ?>
    <div id="age-verify-overlay" class="fixed inset-0 z-[9999] bg-black/95 backdrop-blur-md flex items-center justify-center p-4">
        <div class="bg-zinc-900 border border-zinc-800 p-8 max-w-md w-full text-center space-y-6 rounded-2xl shadow-2xl">
            <div class="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-full flex items-center justify-center mx-auto">
                <span class="text-red-500 font-bold text-xl">18+</span>
            </div>
            <div class="space-y-2">
                <h2 class="text-2xl font-bold text-white tracking-tight">Age Verification Required</h2>
                <p class="text-zinc-400 text-sm">You must be at least 18 years of age and a qualified researcher to enter this site.</p>
            </div>
            <div class="grid grid-cols-2 gap-4 pt-4">
                <button onclick="verifyAge(true)" class="bg-white text-black font-bold py-3 rounded-xl hover:bg-zinc-200 transition-all">I AM 18+</button>
                <button onclick="window.location.href='https://google.com'" class="bg-zinc-800 text-white font-bold py-3 rounded-xl hover:bg-zinc-700 transition-all">EXIT</button>
            </div>
            <p class="text-[10px] text-zinc-500 uppercase tracking-widest leading-relaxed pt-4">
                BY ENTERING, YOU AGREE TO OUR TERMS OF SERVICE AND PRIVACY POLICY. ALL PRODUCTS ARE FOR RESEARCH USE ONLY.
            </p>
        </div>
    </div>
    <script>
    function verifyAge(verified) {
        if (verified) {
            const date = new Date();
            date.setTime(date.getTime() + (30 * 24 * 60 * 60 * 1000)); // 30 days
            document.cookie = "helivex_age_verified=true; expires=" + date.toUTCString() + "; path=/; SameSite=Strict; Secure";
            document.getElementById('age-verify-overlay').remove();
        }
    }
    </script>
    <?php
}
add_action('wp_footer', 'helivex_age_verification_modal');

// 4. ACH/Plaid Data Security Logic (AES-256 Placeholder)
function helivex_encrypt_sensitive_data($data) {
    $key = hash('sha256', AUTH_KEY); // Use WP Auth Key for salt
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

function helivex_decrypt_sensitive_data($data) {
    $key = hash('sha256', AUTH_KEY);
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}

// 5. Fraud Prevention: Log Checkout IPs & User Agents
add_action('woocommerce_checkout_order_processed', 'helivex_log_fraud_data', 10, 3);
function helivex_log_fraud_data($order_id, $posted_data, $order) {
    update_post_meta($order_id, '_customer_ip', $_SERVER['REMOTE_ADDR']);
    update_post_meta($order_id, '_customer_user_agent', $_SERVER['HTTP_USER_AGENT']);
    update_post_meta($order_id, '_compliance_timestamp', current_time('mysql'));
}

/**
 * Enforce Mandatory Registration & Redirect
 */
function helivex_enforce_registration() {
    if (!is_user_logged_in() && (is_checkout() || is_cart())) {
        wc_add_notice(__('You must register an account and log in to initiate a research protocol purchase.', 'helivex'), 'error');
        wp_safe_redirect(get_permalink(get_option('woocommerce_myaccount_page_id')));
        exit;
    }
}
add_action('template_redirect', 'helivex_enforce_registration');

// Redirect after registration to the shop or previous page
function helivex_registration_redirect($redirect) {
    return wc_get_page_permalink('shop');
}
add_filter('woocommerce_registration_redirect', 'helivex_registration_redirect');

/**
 * Product Importer
 */
require_once get_template_directory() . '/import-products.php';

/**
 * Programmatic Page Creation for Compliance & Trust
 */
function helivex_setup_compliance_pages() {
    $pages = [
        'about' => [
            'title'    => 'About Our Laboratory',
            'content'  => '',
            'template' => 'page-about.php',
        ],
        'compliance' => [
            'title'    => 'RUO Compliance & Standards',
            'content'  => '',
            'template' => 'page-compliance.php',
        ],
        'contact' => [
            'title'    => 'Contact Laboratory Support',
            'content'  => '',
            'template' => 'page-contact.php',
        ],
        'coa' => [
            'title'    => 'Certificate of Analysis (COA) Archive',
            'content'  => '',
            'template' => 'page-coa.php',
        ],
        'faq' => [
            'title'    => 'Frequently Asked Questions',
            'content'  => '',
            'template' => 'page-faq.php',
        ],
        'privacy-policy' => [
            'title'    => 'Privacy Policy (CCPA/CPRA Compliant)',
            'content'  => '',
            'template' => 'page-privacy.php',
        ],
        'terms-of-service' => [
            'title'    => 'Terms of Service & Research Agreement',
            'content'  => '',
            'template' => 'page-tos.php',
        ],
        'shipping-returns' => [
            'title'    => 'Shipping & Returns Policy',
            'content'  => '',
            'template' => 'page-shipping-returns.php',
        ],
        'do-not-sell-my-info' => [
            'title'    => 'Do Not Sell My Personal Information',
            'content'  => '',
            'template' => 'page-dns.php',
        ],
    ];

    foreach ($pages as $slug => $data) {
        $query = new WP_Query([
            'post_type'  => 'page',
            'name'       => $slug,
            'post_status' => 'any',
        ]);

        if (!$query->have_posts()) {
            $page_id = wp_insert_post([
                'post_title'   => $data['title'],
                'post_content' => $data['content'],
                'post_status'  => 'publish',
                'post_type'    => 'page',
                'post_name'    => $slug,
            ]);

            if ($page_id && !is_wp_error($page_id)) {
                update_post_meta($page_id, '_wp_page_template', $data['template']);
            }
        } else {
            // FORCE UPDATE: If the page exists but isn't using our template, force it.
            // This fixes issues where WordPress creates a default privacy page with "suggested text".
            $existing_page = $query->posts[0];
            update_post_meta($existing_page->ID, '_wp_page_template', $data['template']);
            
            // If it's the privacy policy, we also want to set it as the official WP privacy page
            if ($slug === 'privacy-policy') {
                update_option('wp_page_for_privacy_policy', $existing_page->ID);
            }
        }
    }
}
add_action('admin_init', 'helivex_setup_compliance_pages');
