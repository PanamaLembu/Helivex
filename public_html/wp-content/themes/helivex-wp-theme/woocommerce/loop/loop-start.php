<?php
/**
 * Product loop start
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/loop/loop-start.php.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="products columns-<?php echo esc_attr( wc_get_loop_prop( 'columns' ) ); ?> grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
