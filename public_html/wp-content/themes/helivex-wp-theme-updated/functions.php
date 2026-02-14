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
                <h2 class="text-2xl font-bold text-white tracking-tight"><?php ehvx('age_heading', 'Age Verification Required'); ?></h2>
                <p class="text-zinc-400 text-sm"><?php ehvx('age_description', 'You must be at least 18 years of age and a qualified researcher to enter this site.'); ?></p>
            </div>
            <div class="grid grid-cols-2 gap-4 pt-4">
                <button onclick="verifyAge(true)" class="bg-white text-black font-bold py-3 rounded-xl hover:bg-zinc-200 transition-all"><?php ehvx('age_confirm_btn', 'I AM 18+'); ?></button>
                <button onclick="window.location.href='https://google.com'" class="bg-zinc-800 text-white font-bold py-3 rounded-xl hover:bg-zinc-700 transition-all">EXIT</button>
            </div>
            <p class="text-[10px] text-zinc-500 uppercase tracking-widest leading-relaxed pt-4">
                <?php ehvx('age_disclaimer', 'BY ENTERING, YOU AGREE TO OUR TERMS OF SERVICE AND PRIVACY POLICY. ALL PRODUCTS ARE FOR RESEARCH USE ONLY.'); ?>
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

/**
 * ============================================================
 * HELIVEX TEXT EDITOR - Edit All Site Text from Admin Panel
 * ============================================================
 */

/**
 * Get editable text by key, with fallback to default
 */
function hvx($key, $default = '') {
    $texts = get_option('helivex_site_texts', []);
    if (isset($texts[$key]) && $texts[$key] !== '') {
        return $texts[$key];
    }
    return $default;
}

/**
 * Echo editable text (shorthand)
 */
function ehvx($key, $default = '') {
    echo hvx($key, $default);
}

/**
 * Get all default text values organized by page/section
 */
function helivex_get_default_texts() {
    return [
        // ===== HEADER =====
        'header_logo_text' => 'HELIVEX LABS',
        'header_secure_link' => 'SECURE_LINK: ACTIVE',
        'header_regulatory_banner' => 'RESEARCH USE ONLY — These products are intended strictly for laboratory research and are not approved by the FDA for human consumption, therapeutic use, or any clinical application.',

        // ===== HOMEPAGE HERO =====
        'hero_badge' => 'ISO 9001:2015 Certified Sourcing',
        'hero_heading_line1' => 'PRECISION IN',
        'hero_heading_line2' => 'RESEARCH.',
        'hero_description' => 'Helivex Labs provides the scientific community with ultra-pure peptides and research compounds, setting the gold standard for integrity and reliability.',
        'hero_cta_primary' => 'SHOP RESEARCH PEPTIDES',
        'hero_cta_secondary' => 'ABOUT OUR STANDARDS',

        // ===== HOMEPAGE MISSION =====
        'mission_heading' => '99%+ Pure Research Standards',
        'mission_quote' => 'Precision is not just a goal; it is our baseline protocol.',
        'mission_description' => 'At Helivex Labs, our purpose is to deliver research peptides at fair, transparent prices. We are built on a foundation of trust, integrity, and uncompromising standards.',
        'mission_cta' => 'ABOUT OUR STANDARDS',

        // ===== HOMEPAGE TRUST BADGES =====
        'trust_badge_1_title' => '99% PURE & TESTED',
        'trust_badge_1_desc' => 'Rigorous third-party testing.',
        'trust_badge_2_title' => 'SHIPS IN 3-5 DAYS',
        'trust_badge_2_desc' => 'Fast, reliable USA shipping.',
        'trust_badge_3_title' => 'RESEARCH USE ONLY',
        'trust_badge_3_desc' => 'For laboratory and scientific use.',

        // ===== HOMEPAGE FEATURED PRODUCTS =====
        'featured_label' => 'Product Catalog',
        'featured_heading' => 'FEATURED COMPOUNDS',
        'featured_description' => 'Precision-engineered research materials for clinical study.',
        'featured_cta' => 'SHOP ALL RESEARCH PEPTIDES',

        // ===== HOMEPAGE VIAL SECTION =====
        'vial_section_badge' => 'Structural Analysis',
        'vial_section_heading_1' => 'MOLECULAR',
        'vial_section_heading_2' => 'INTEGRITY.',
        'vial_dot1_label' => 'Purity Level',
        'vial_dot1_text' => '99%+ Pure Research Grade Peptide, verified by third-party HPLC testing.',
        'vial_dot1_note' => 'Note: Analysis reflects sample COA qualities.',
        'vial_dot2_label' => 'Vacuum Sealed',
        'vial_dot2_text' => 'Lyophilized powder stored under nitrogen for maximum stability and shelf-life.',
        'vial_dot3_label' => 'Cold Storage',
        'vial_dot3_text' => 'Ships in temperature-controlled packaging to maintain molecular chain integrity.',

        // ===== HOMEPAGE FAQ =====
        'home_faq_heading' => 'FREQUENTLY ASKED QUESTIONS',
        'home_faq_1_q' => 'What are the products from Helivex Labs intended for?',
        'home_faq_1_a' => 'All items sold by Helivex Labs are strictly for laboratory research use only. They are not for human or animal consumption, not for therapeutic use, and not cleared for incorporation into food, cosmetics, medical devices, or drugs.',
        'home_faq_2_q' => 'Do you provide Certificates of Analysis (COAs)?',
        'home_faq_2_a' => 'Yes. Certificates of Analysis are available for most products. We ensure 99% purity through rigorous third-party testing to provide the highest quality research peptides online.',
        'home_faq_3_q' => 'What is your shipping time?',
        'home_faq_3_a' => 'Orders are processed quickly and shipped from the USA. You can expect delivery within 3-5 business days from the day you receive your tracking info. We provide fast, reliable peptide research supplies to your laboratory.',
        'home_faq_4_q' => 'How can I buy peptides online safely?',
        'home_faq_4_a' => 'When you buy research peptides online from Helivex Labs, you are guaranteed 99% purity, secure encrypted transactions, and discrete, fast USA shipping. All our compounds undergo strict quality control.',

        // ===== HOMEPAGE MOLECULAR DIAGNOSTICS =====
        'diag_label' => 'Quantum Lab Interface v4.0',
        'diag_heading_1' => 'ADVANCED',
        'diag_heading_2' => 'MOLECULAR',
        'diag_heading_3' => 'DIAGNOSTICS',
        'diag_description' => 'Real-time synthesis monitoring and purity verification. Our medical-grade infrastructure ensures every batch meets the Helivex Gold Standard.',
        'diag_status' => 'Core Status: Nominal // Integrity Verified',

        // ===== HOMEPAGE HUD NODES =====
        'hud_node1_label' => 'NODE_V.104',
        'hud_node1_value' => 'PURITY 99.242%',
        'hud_node2_label' => 'NODE_V.105',
        'hud_node2_value' => 'STERILITY - NO GROWTH',
        'hud_node3_label' => 'NODE_V.106',
        'hud_node3_value' => 'ENDOTOXINS < 0.0239 EU/mg',
        'hud_node4_label' => 'NODE_V.107',
        'hud_node4_value' => 'QUANTITY 30.02mg',

        // ===== FOOTER =====
        'footer_logo_text' => 'HELIVEX LABS',
        'footer_description' => 'Premium quality research peptides and compounds. Tested for 99% purity and delivered with integrity to the scientific community.',
        'footer_email' => 'support@helivexlabs.com',
        'footer_phone' => '+1 (800) 555-0199',
        'footer_address' => '123 Research Way, Suite 400, Austin, TX 78701, USA',
        'footer_copyright' => 'Helivex Labs. All Rights Reserved.',
        'footer_payment_1' => 'Plaid Secured',
        'footer_payment_2' => 'Crypto (BTC/ETH)',
        'footer_secure_badge' => 'SECURE PLAID LINK',
        'footer_encrypt_badge' => 'AES-256 Encrypted',

        // ===== CONTACT PAGE =====
        'contact_heading' => 'Contact Laboratory Support',
        'contact_description' => 'Our technical team is available for laboratory inquiries, batch verification, and fulfillment support.',
        'contact_email' => 'support@helivexlabs.com',
        'contact_phone' => '+1 (800) 555-0199',
        'contact_address' => '123 Research Way, Suite 400, Austin, TX 78701, USA',
        'contact_hours' => 'Mon — Fri: 9AM - 6PM CST',
        'contact_hours_note' => 'Lab fulfillment is paused on federal holidays to maintain shipping integrity.',
        'contact_form_button' => 'Send Laboratory Inquiry',

        // ===== ABOUT PAGE =====
        'about_established' => 'Established 2026',
        'about_heading' => 'The Science of Integrity',
        'about_description' => 'Dedicated to providing the global scientific community with high-purity research compounds and analytical data.',
        'about_mission_title' => 'Our Laboratory Mission',
        'about_mission_text' => 'Helivex Labs was founded on a singular principle: Precision. We ensure 99%+ purity by utilizing state-of-the-art laboratory analysis from industry leaders including Janoshik, Freedom, Chromate, and Vanguard. Every vial is subjected to rigorous HPLC and Mass Spectrometry testing to maintain our uncompromising standards.',
        'about_purity_stat' => '99%+ Average Purity Rating',

        // ===== AGE VERIFICATION =====
        'age_heading' => 'Age Verification Required',
        'age_description' => 'You must be at least 18 years of age and a qualified researcher to enter this site.',
        'age_confirm_btn' => 'I AM 18+',
        'age_disclaimer' => 'BY ENTERING, YOU AGREE TO OUR TERMS OF SERVICE AND PRIVACY POLICY. ALL PRODUCTS ARE FOR RESEARCH USE ONLY.',

        // ===== PRODUCT PAGE =====
        'product_badge' => 'Laboratory Standard',
        'product_purity_badge' => '99%+ PURITY VERIFIED',
        'product_trust_1' => 'Third-Party Vetted',
        'product_trust_2' => 'Fast USA Shipping',
        'product_trust_3' => 'Research Grade',
    ];
}

/**
 * Define text sections for the admin UI
 */
function helivex_get_text_sections() {
    return [
        'Header' => ['header_logo_text', 'header_secure_link', 'header_regulatory_banner'],
        'Homepage — Hero' => ['hero_badge', 'hero_heading_line1', 'hero_heading_line2', 'hero_description', 'hero_cta_primary', 'hero_cta_secondary'],
        'Homepage — Mission' => ['mission_heading', 'mission_quote', 'mission_description', 'mission_cta'],
        'Homepage — Trust Badges' => ['trust_badge_1_title', 'trust_badge_1_desc', 'trust_badge_2_title', 'trust_badge_2_desc', 'trust_badge_3_title', 'trust_badge_3_desc'],
        'Homepage — Featured Products' => ['featured_label', 'featured_heading', 'featured_description', 'featured_cta'],
        'Homepage — Vial Section' => ['vial_section_badge', 'vial_section_heading_1', 'vial_section_heading_2', 'vial_dot1_label', 'vial_dot1_text', 'vial_dot1_note', 'vial_dot2_label', 'vial_dot2_text', 'vial_dot3_label', 'vial_dot3_text'],
        'Homepage — FAQ' => ['home_faq_heading', 'home_faq_1_q', 'home_faq_1_a', 'home_faq_2_q', 'home_faq_2_a', 'home_faq_3_q', 'home_faq_3_a', 'home_faq_4_q', 'home_faq_4_a'],
        'Homepage — Molecular Diagnostics' => ['diag_label', 'diag_heading_1', 'diag_heading_2', 'diag_heading_3', 'diag_description', 'diag_status'],
        'Homepage — HUD Nodes' => ['hud_node1_label', 'hud_node1_value', 'hud_node2_label', 'hud_node2_value', 'hud_node3_label', 'hud_node3_value', 'hud_node4_label', 'hud_node4_value'],
        'Footer' => ['footer_logo_text', 'footer_description', 'footer_email', 'footer_phone', 'footer_address', 'footer_copyright', 'footer_payment_1', 'footer_payment_2', 'footer_secure_badge', 'footer_encrypt_badge'],
        'Contact Page' => ['contact_heading', 'contact_description', 'contact_email', 'contact_phone', 'contact_address', 'contact_hours', 'contact_hours_note', 'contact_form_button'],
        'About Page' => ['about_established', 'about_heading', 'about_description', 'about_mission_title', 'about_mission_text', 'about_purity_stat'],
        'Age Verification' => ['age_heading', 'age_description', 'age_confirm_btn', 'age_disclaimer'],
        'Product Page' => ['product_badge', 'product_purity_badge', 'product_trust_1', 'product_trust_2', 'product_trust_3'],
    ];
}

/**
 * Register the admin menu page
 */
function helivex_text_editor_menu() {
    add_menu_page(
        'Site Text Editor',
        'Text Editor',
        'manage_options',
        'helivex-text-editor',
        'helivex_text_editor_page',
        'dashicons-edit-page',
        30
    );
}
add_action('admin_menu', 'helivex_text_editor_menu');

/**
 * Handle saving text via AJAX
 */
function helivex_save_site_texts() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    check_ajax_referer('helivex_text_editor_nonce', 'nonce');

    $texts = isset($_POST['texts']) ? $_POST['texts'] : [];
    $sanitized = [];
    foreach ($texts as $key => $value) {
        $sanitized[sanitize_key($key)] = wp_kses_post(stripslashes($value));
    }

    update_option('helivex_site_texts', $sanitized);
    wp_send_json_success('All text saved successfully!');
}
add_action('wp_ajax_helivex_save_texts', 'helivex_save_site_texts');

/**
 * Reset all texts to defaults via AJAX
 */
function helivex_reset_site_texts() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }
    check_ajax_referer('helivex_text_editor_nonce', 'nonce');
    delete_option('helivex_site_texts');
    wp_send_json_success('Reset to defaults!');
}
add_action('wp_ajax_helivex_reset_texts', 'helivex_reset_site_texts');

/**
 * Render the Text Editor admin page
 */
function helivex_text_editor_page() {
    $defaults = helivex_get_default_texts();
    $saved = get_option('helivex_site_texts', []);
    $sections = helivex_get_text_sections();
    $nonce = wp_create_nonce('helivex_text_editor_nonce');
    ?>
    <style>
        .hvx-wrap { max-width: 960px; margin: 20px auto; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .hvx-header { background: linear-gradient(135deg, #8B1A1A 0%, #4A0E0E 100%); color: white; padding: 30px 40px; border-radius: 16px 16px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .hvx-header h1 { margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; }
        .hvx-header p { margin: 5px 0 0; opacity: 0.7; font-size: 13px; }
        .hvx-body { background: #fff; border: 1px solid #e5e5e5; border-top: 0; border-radius: 0 0 16px 16px; padding: 0; }
        .hvx-section { border-bottom: 1px solid #f0f0f0; }
        .hvx-section:last-child { border-bottom: 0; }
        .hvx-section-header { padding: 20px 40px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; background: #fafafa; transition: background 0.2s; user-select: none; }
        .hvx-section-header:hover { background: #f5f0f0; }
        .hvx-section-header h2 { margin: 0; font-size: 15px; font-weight: 700; color: #1a1a1a; text-transform: uppercase; letter-spacing: 1px; }
        .hvx-section-header .hvx-count { background: #8B1A1A; color: white; padding: 2px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; }
        .hvx-section-header .hvx-arrow { font-size: 18px; color: #999; transition: transform 0.3s; }
        .hvx-section-header.open .hvx-arrow { transform: rotate(180deg); }
        .hvx-section-fields { display: none; padding: 20px 40px 30px; }
        .hvx-section-fields.open { display: block; }
        .hvx-field { margin-bottom: 20px; }
        .hvx-field label { display: block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #8B1A1A; margin-bottom: 6px; }
        .hvx-field input[type="text"], .hvx-field textarea { width: 100%; padding: 12px 16px; border: 1px solid #e0e0e0; border-radius: 10px; font-size: 14px; font-family: inherit; transition: border-color 0.2s, box-shadow 0.2s; box-sizing: border-box; }
        .hvx-field input[type="text"]:focus, .hvx-field textarea:focus { outline: none; border-color: #8B1A1A; box-shadow: 0 0 0 3px rgba(139,26,26,0.1); }
        .hvx-field textarea { min-height: 80px; resize: vertical; }
        .hvx-field .hvx-default { font-size: 11px; color: #999; margin-top: 4px; font-style: italic; }
        .hvx-actions { padding: 20px 40px 30px; display: flex; gap: 12px; justify-content: flex-end; border-top: 1px solid #f0f0f0; position: sticky; bottom: 0; background: white; border-radius: 0 0 16px 16px; z-index: 10; }
        .hvx-btn { padding: 12px 32px; border-radius: 10px; font-size: 13px; font-weight: 700; cursor: pointer; border: none; transition: all 0.2s; text-transform: uppercase; letter-spacing: 1px; }
        .hvx-btn-save { background: #8B1A1A; color: white; }
        .hvx-btn-save:hover { background: #6d1414; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(139,26,26,0.3); }
        .hvx-btn-reset { background: #f5f5f5; color: #666; }
        .hvx-btn-reset:hover { background: #eee; }
        .hvx-toast { position: fixed; bottom: 30px; right: 30px; padding: 16px 28px; border-radius: 12px; color: white; font-weight: 700; font-size: 14px; z-index: 9999; transform: translateY(100px); opacity: 0; transition: all 0.4s; }
        .hvx-toast.show { transform: translateY(0); opacity: 1; }
        .hvx-toast.success { background: #16a34a; }
        .hvx-toast.error { background: #dc2626; }
        .hvx-search { padding: 20px 40px; border-bottom: 1px solid #f0f0f0; }
        .hvx-search input { width: 100%; padding: 12px 16px 12px 44px; border: 1px solid #e0e0e0; border-radius: 10px; font-size: 14px; background: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='%23999' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E") 14px center no-repeat; box-sizing: border-box; }
        .hvx-search input:focus { outline: none; border-color: #8B1A1A; box-shadow: 0 0 0 3px rgba(139,26,26,0.1); }
        .hvx-field.hidden { display: none; }
        .hvx-section.hidden { display: none; }
    </style>

    <div class="hvx-wrap">
        <div class="hvx-header">
            <div>
                <h1>Site Text Editor</h1>
                <p>Edit all text across your website from one place.</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 11px; opacity: 0.6; text-transform: uppercase; letter-spacing: 2px;">Helivex Labs</div>
                <div style="font-size: 13px; margin-top: 4px;"><?php echo count($defaults); ?> editable fields</div>
            </div>
        </div>

        <div class="hvx-body">
            <div class="hvx-search">
                <input type="text" id="hvx-search-input" placeholder="Search text fields... (e.g. &quot;email&quot;, &quot;hero&quot;, &quot;shipping&quot;)">
            </div>

            <form id="hvx-text-form">
                <?php foreach ($sections as $section_name => $keys): ?>
                    <div class="hvx-section" data-section="<?php echo esc_attr($section_name); ?>">
                        <div class="hvx-section-header" onclick="toggleSection(this)">
                            <h2><?php echo esc_html($section_name); ?></h2>
                            <div style="display:flex;align-items:center;gap:12px;">
                                <span class="hvx-count"><?php echo count($keys); ?></span>
                                <span class="hvx-arrow">&#9660;</span>
                            </div>
                        </div>
                        <div class="hvx-section-fields">
                            <?php foreach ($keys as $key):
                                $default = isset($defaults[$key]) ? $defaults[$key] : '';
                                $current = isset($saved[$key]) ? $saved[$key] : '';
                                $display_value = $current !== '' ? $current : $default;
                                $is_long = strlen($default) > 80;
                                $label = ucwords(str_replace(['_', 'hvx'], [' ', ''], $key));
                            ?>
                                <div class="hvx-field" data-key="<?php echo esc_attr($key); ?>">
                                    <label for="hvx-<?php echo esc_attr($key); ?>"><?php echo esc_html($label); ?></label>
                                    <?php if ($is_long): ?>
                                        <textarea id="hvx-<?php echo esc_attr($key); ?>" name="texts[<?php echo esc_attr($key); ?>]" rows="3"><?php echo esc_textarea($display_value); ?></textarea>
                                    <?php else: ?>
                                        <input type="text" id="hvx-<?php echo esc_attr($key); ?>" name="texts[<?php echo esc_attr($key); ?>]" value="<?php echo esc_attr($display_value); ?>">
                                    <?php endif; ?>
                                    <?php if ($current !== '' && $current !== $default): ?>
                                        <div class="hvx-default">Default: <?php echo esc_html(mb_substr($default, 0, 100)); ?><?php echo strlen($default) > 100 ? '...' : ''; ?></div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </form>

            <div class="hvx-actions">
                <button type="button" class="hvx-btn hvx-btn-reset" onclick="resetTexts()">Reset All to Defaults</button>
                <button type="button" class="hvx-btn hvx-btn-save" id="hvx-save-btn" onclick="saveTexts()">Save All Changes</button>
            </div>
        </div>
    </div>

    <div class="hvx-toast" id="hvx-toast"></div>

    <script>
    function toggleSection(el) {
        el.classList.toggle('open');
        el.nextElementSibling.classList.toggle('open');
    }

    function showToast(message, type) {
        var toast = document.getElementById('hvx-toast');
        toast.textContent = message;
        toast.className = 'hvx-toast ' + type + ' show';
        setTimeout(function() { toast.classList.remove('show'); }, 3000);
    }

    function saveTexts() {
        var btn = document.getElementById('hvx-save-btn');
        btn.textContent = 'SAVING...';
        btn.disabled = true;

        var formData = new FormData(document.getElementById('hvx-text-form'));
        formData.append('action', 'helivex_save_texts');
        formData.append('nonce', '<?php echo $nonce; ?>');

        fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(function(res) {
            if (res.success) {
                showToast('All text saved successfully!', 'success');
            } else {
                showToast('Error: ' + res.data, 'error');
            }
            btn.textContent = 'SAVE ALL CHANGES';
            btn.disabled = false;
        })
        .catch(function() {
            showToast('Network error. Please try again.', 'error');
            btn.textContent = 'SAVE ALL CHANGES';
            btn.disabled = false;
        });
    }

    function resetTexts() {
        if (!confirm('Are you sure? This will reset ALL text to the original defaults.')) return;

        var formData = new FormData();
        formData.append('action', 'helivex_reset_texts');
        formData.append('nonce', '<?php echo $nonce; ?>');

        fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(function(res) {
            if (res.success) {
                showToast('Reset to defaults! Reloading...', 'success');
                setTimeout(function() { location.reload(); }, 1000);
            } else {
                showToast('Error resetting.', 'error');
            }
        });
    }

    // Search functionality
    document.getElementById('hvx-search-input').addEventListener('input', function() {
        var query = this.value.toLowerCase();
        document.querySelectorAll('.hvx-section').forEach(function(section) {
            var fields = section.querySelectorAll('.hvx-field');
            var hasVisible = false;
            fields.forEach(function(field) {
                var key = field.getAttribute('data-key').toLowerCase();
                var input = field.querySelector('input, textarea');
                var val = input ? input.value.toLowerCase() : '';
                var label = field.querySelector('label').textContent.toLowerCase();
                if (key.indexOf(query) > -1 || val.indexOf(query) > -1 || label.indexOf(query) > -1) {
                    field.classList.remove('hidden');
                    hasVisible = true;
                } else {
                    field.classList.add('hidden');
                }
            });
            if (query === '') {
                section.classList.remove('hidden');
                fields.forEach(function(f) { f.classList.remove('hidden'); });
            } else if (hasVisible) {
                section.classList.remove('hidden');
                section.querySelector('.hvx-section-header').classList.add('open');
                section.querySelector('.hvx-section-fields').classList.add('open');
            } else {
                section.classList.add('hidden');
            }
        });
    });
    </script>
    <?php
}
