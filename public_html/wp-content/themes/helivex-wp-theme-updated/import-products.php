<?php
/**
 * Helivex Product Importer
 * Handles the one-time import of products from woocommerce-products.csv
 */

function helivex_import_products_from_csv() {
    if (!isset($_GET['helivex_import']) || $_GET['helivex_import'] !== '1') {
        return;
    }

    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    // Global image update trigger
    if (isset($_GET['helivex_update_all_images']) && $_GET['helivex_update_all_images'] === '1') {
        $image_name = isset($_GET['image']) ? $_GET['image'] : 'vial-red-cap.png';
        $products = wc_get_products(['limit' => -1]);
        $count = 0;
        foreach ($products as $product) {
            helivex_set_product_image_from_url($product->get_id(), $image_name);
            $count++;
        }
        wp_die("Updated $count products with image: $image_name");
    }

    // Try multiple locations for the CSV file
    $csv_name = isset($_GET['csv']) ? $_GET['csv'] : 'woocommerce-products.csv';
    $locations = [
        ABSPATH . $csv_name,
        get_template_directory() . '/' . $csv_name,
        dirname(get_template_directory()) . '/' . $csv_name
    ];

    $csv_file = '';
    foreach ($locations as $location) {
        if (file_exists($location)) {
            $csv_file = $location;
            break;
        }
    }

    if (!$csv_file) {
        $error_msg = 'CSV file not found. Please upload "woocommerce-products.csv" to either:<br>';
        $error_msg .= '1. Your site root: ' . ABSPATH . '<br>';
        $error_msg .= '2. Your theme folder: ' . get_template_directory();
        wp_die($error_msg);
    }

    $handle = fopen($csv_file, 'r');
    if (!$handle) {
        wp_die('Could not open CSV file');
    }

    // Skip header
    $header = fgetcsv($handle);
    
    $products_created = 0;
    $variations_created = 0;

    // First pass: Create parent variable products and simple products
    $parents = [];
    $rows = [];
    while (($data = fgetcsv($handle)) !== FALSE) {
        $rows[] = $data;
        $type = strtolower($data[0]);
        
        // Handle EZ Format detection (if index 1 is 'simple' or 'variable', it's likely EZ format)
        $is_ez = (isset($data[1]) && (strtolower($data[1]) === 'simple' || strtolower($data[1]) === 'variable'));
        
        if ($is_ez) {
            $name = $data[0];
            $type = strtolower($data[1]);
            $sku = $data[2];
            $price = $data[4]; // Regular Price
            $categories = explode(',', $data[5]);
            $image_url = $data[6];
            $attr_name = $data[7];
            $attr_values = $data[8];
            
            // Research-specific brief descriptions
            $descriptions = [
                'Semaglutide' => 'A potent GLP-1 receptor agonist utilized in clinical research to study glycemic regulation and metabolic appetite control pathways.',
                'Tirzepatide' => 'A dual GIP and GLP-1 receptor agonist engineered for advanced study of synergistic metabolic signaling and energy homeostasis.',
                'Retatrutide' => 'A triple agonist (GLP-1, GIP, and glucagon receptors) for experimental analysis of multi-pathway metabolic enhancement.',
                'BPC-157' => 'A pentadecapeptide derived from gastric protein, investigated for its regenerative properties in tendon, muscle, and ligament tissue repair.',
                'TB-500' => 'A synthetic version of Thymosin Beta-4, primarily researched for its role in cellular migration, angiogenesis, and tissue wound healing.',
                'AOD-9604' => 'A C-terminal fragment of Human Growth Hormone (HGH) studied for its lipolytic properties without influencing systemic growth or insulin resistance.',
                'Ipamorelin' => 'A selective growth hormone secretagogue researched for its ability to stimulate GH release while maintaining metabolic selectivity.',
                'Cagrilintide' => 'A long-acting amylin analogue studied for its interaction with GLP-1 pathways in the regulation of satiety and energy expenditure.',
                'Melanotan II' => 'A cyclic heptapeptide melanocortin receptor agonist investigated for its effects on skin pigmentation and photoprotective research.'
            ];

            $description = "High purity $name for research purposes.";
            foreach ($descriptions as $key => $val) {
                if (stripos($name, $key) !== false) {
                    $description = $val;
                    break;
                }
            }
        } else {
            $type = strtolower($data[0]);
            $sku = $data[1];
            $name = $data[2];
            $description = $data[3];
            $categories = explode(',', $data[4]);
            $image_url = $data[5];
            $attr_name = $data[6];
            $attr_values = $data[7];
            $price = isset($data[11]) ? $data[11] : '';
        }

        if ($type === 'variable' || $type === 'simple') {
            // Check if product exists
            $product_id = wc_get_product_id_by_sku($sku);
            
            if ($type === 'variable') {
                $product = $product_id ? wc_get_product($product_id) : new WC_Product_Variable();
            } else {
                $product = $product_id ? wc_get_product($product_id) : new WC_Product_Simple();
            }

            $product->set_sku($sku);
            $product->set_name($name);
            $product->set_description($description);
            $product->set_status('publish');
            
            if ($type === 'simple' && $price) {
                $product->set_regular_price($price);
            }
            
            // Set Categories
            $cat_ids = [];
            foreach ($categories as $cat_name) {
                $cat_name = trim($cat_name);
                if (!$cat_name) continue;
                $term = get_term_by('name', $cat_name, 'product_cat');
                if (!$term) {
                    $term = wp_insert_term($cat_name, 'product_cat');
                    if (!is_wp_error($term)) {
                        $cat_ids[] = $term['term_id'];
                    }
                } else {
                    $cat_ids[] = $term->term_id;
                }
            }
            $product->set_category_ids($cat_ids);

            // Set Attributes
            if ($attr_name && $attr_values) {
                $attribute = new WC_Product_Attribute();
                $attribute->set_name($attr_name);
                $attribute->set_options(array_map('trim', explode(',', $attr_values)));
                $attribute->set_position(0);
                $attribute->set_visible(true);
                $attribute->set_variation($type === 'variable');
                $product->set_attributes([$attribute]);
            }

            $product_id = $product->save();
            if ($type === 'variable') {
                $parents[$sku] = $product_id;
            }
            $products_created++;

            // Handle Image
            if ($image_url) {
                helivex_set_product_image_from_url($product_id, $image_url);
            }
        }
    }

    // Second pass: Create variations (only for non-EZ format or if parents exist)
    foreach ($rows as $data) {
        $type = strtolower($data[0]);
        $is_ez = (isset($data[1]) && (strtolower($data[1]) === 'simple' || strtolower($data[1]) === 'variable'));
        
        if ($is_ez) continue; // EZ format currently doesn't define variations in separate rows

        if ($type === 'variation') {
            $sku = $data[1];
            $name = $data[2];
            $parent_sku = $data[10];
            $price = $data[11];
            $strength_val = trim($data[7]);

            if (isset($parents[$parent_sku])) {
                $parent_id = $parents[$parent_sku];
                
                $variation_id = wc_get_product_id_by_sku($sku);
                $variation = $variation_id ? wc_get_product($variation_id) : new WC_Product_Variation();
                
                $variation->set_parent_id($parent_id);
                $variation->set_sku($sku);
                $variation->set_name($name);
                $variation->set_regular_price($price);
                $variation->set_status('publish');
                
                // Set variation attribute - match parent attribute slug
                $variation->set_attributes(['strength' => $strength_val]);
                
                $variation->save();
                $variations_created++;
            }
        }
    }

    fclose($handle);
    
    echo "Import Complete! Created/Updated $products_created variable products and $variations_created variations.";
    exit;
}

/**
 * Helper to set product image from URL
 */
function helivex_set_product_image_from_url($product_id, $url) {
    require_once(ABSPATH . 'wp-admin/includes/media.php');
    require_once(ABSPATH . 'wp-admin/includes/file.php');
    require_once(ABSPATH . 'wp-admin/includes/image.php');

    // Check if image already exists in media library by checking the filename
    $filename = basename($url);
    
    // If it's just a filename (no http/https), look in theme assets
    if (!preg_match('~^(?:f|ht)tps?://~i', $url)) {
        $local_path = get_template_directory() . '/assets/images/' . $url;
        if (file_exists($local_path)) {
            // Upload to media library from local path
            $upload = wp_upload_bits($filename, null, file_get_contents($local_path));
            if (!$upload['error']) {
                $url = $upload['url'];
            }
        }
    }

    $existing_id = attachment_url_to_postid($url);

    // Try to find by title/filename
    global $wpdb;
    $attachment_id = $wpdb->get_var($wpdb->prepare("SELECT post_id FROM $wpdb->postmeta WHERE meta_key = '_wp_attached_file' AND meta_value LIKE %s", '%' . $filename . '%'));

    if (!$attachment_id) {
        $attachment_id = media_sideload_image($url, $product_id, null, 'id');
    }

    if (!is_wp_error($attachment_id)) {
        set_post_thumbnail($product_id, $attachment_id);
    }
}

add_action('admin_init', 'helivex_import_products_from_csv');
