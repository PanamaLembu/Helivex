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

    // Try multiple locations for the CSV file
    $locations = [
        ABSPATH . 'woocommerce-products.csv',
        get_template_directory() . '/woocommerce-products.csv',
        dirname(get_template_directory()) . '/woocommerce-products.csv' // Root of wp-content/themes/
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

    // First pass: Create parent variable products
    $parents = [];
    $rows = [];
    while (($data = fgetcsv($handle)) !== FALSE) {
        $rows[] = $data;
        if ($data[0] === 'variable') {
            $sku = $data[1];
            $name = $data[2];
            $description = $data[3];
            $categories = explode(',', $data[4]);
            $image_url = $data[5];
            $attr_name = $data[6];
            $attr_values = explode(',', $data[7]);

            // Check if product exists
            $product_id = wc_get_product_id_by_sku($sku);
            if (!$product_id) {
                $product = new WC_Product_Variable();
                $product->set_sku($sku);
            } else {
                $product = wc_get_product($product_id);
            }

            $product->set_name($name);
            $product->set_description($description);
            $product->set_status('publish');
            
            // Set Categories
            $cat_ids = [];
            foreach ($categories as $cat_name) {
                $cat_name = trim($cat_name);
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
            if ($attr_name) {
                $attribute = new WC_Product_Attribute();
                $attribute->set_name($attr_name);
                $attribute->set_options(array_map('trim', $attr_values));
                $attribute->set_position(0);
                $attribute->set_visible(true);
                $attribute->set_variation(true);
                $product->set_attributes([$attribute]);
            }

            $product_id = $product->save();
            $parents[$sku] = $product_id;
            $products_created++;

            // Handle Image
            if ($image_url) {
                helivex_set_product_image_from_url($product_id, $image_url);
            }
        }
    }

    // Second pass: Create variations
    foreach ($rows as $data) {
        if ($data[0] === 'variation') {
            $sku = $data[1];
            $name = $data[2];
            $parent_sku = $data[10];
            $price = $data[11];
            $strength_val = trim($data[7]);

            if (isset($parents[$parent_sku])) {
                $parent_id = $parents[$parent_sku];
                
                $variation_id = wc_get_product_id_by_sku($sku);
                if (!$variation_id) {
                    $variation = new WC_Product_Variation();
                    $variation->set_parent_id($parent_id);
                    $variation->set_sku($sku);
                } else {
                    $variation = wc_get_product($variation_id);
                }

                $variation->set_name($name);
                $variation->set_regular_price($price);
                $variation->set_status('publish');
                
                // Set variation attribute
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
    $existing_id = attachment_url_to_postid($url); // Won't work for external URLs

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
