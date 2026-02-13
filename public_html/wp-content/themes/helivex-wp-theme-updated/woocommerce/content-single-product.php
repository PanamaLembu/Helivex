<?php
/**
 * The template for displaying product detail
 */

defined( 'ABSPATH' ) || exit;

global $product;

if ( ! $product ) {
	return;
}

/**
 * Hook: woocommerce_before_single_product.
 */
do_action( 'woocommerce_before_single_product' );

if ( post_password_required() ) {
	echo get_the_password_form(); // WPCS: XSS ok.
	return;
}
?>

<div id="product-<?php the_ID(); ?>" <?php wc_product_class( 'bg-white', $product ); ?>>
    <!-- Breadcrumbs -->
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <nav class="flex items-center gap-2 text-xs font-medium text-muted-foreground uppercase tracking-widest">
            <a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="hover:text-primary transition-colors">Home</a>
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-3 w-3"><path d="m9 18 6-6-6-6"/></svg>
            <a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="hover:text-primary transition-colors">Shop</a>
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-3 w-3"><path d="m9 18 6-6-6-6"/></svg>
            <span class="text-zinc-900"><?php the_title(); ?></span>
        </nav>
    </div>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 pt-4">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
            <!-- Image Section -->
            <div class="space-y-4">
                <div class="aspect-square relative bg-zinc-50 rounded-3xl border border-border overflow-hidden flex items-center justify-center p-12 group">
                    <?php
                    if ( has_post_thumbnail() ) {
                        the_post_thumbnail( 'full', array( 'class' => 'object-contain drop-shadow-2xl transition-transform duration-700 group-hover:scale-110' ) );
                    }
                    ?>
                    
                    <!-- Purity Badge Overlay -->
                    <div class="absolute top-6 right-6 bg-white/90 backdrop-blur-md border border-primary/20 px-4 py-2 rounded-2xl shadow-xl flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                        <span class="text-[10px] font-black tracking-tighter text-zinc-900 uppercase">99.8% PURITY VERIFIED</span>
                    </div>
                </div>
                
                <!-- Trust Badges -->
                <div class="grid grid-cols-3 gap-4">
                    <div class="bg-zinc-50 p-4 rounded-2xl border border-border flex flex-col items-center text-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-primary"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 11 12 14 15 11"/></svg>
                        <span class="text-[9px] font-bold uppercase tracking-wider">Third-Party Vetted</span>
                    </div>
                    <div class="bg-zinc-50 p-4 rounded-2xl border border-border flex flex-col items-center text-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-primary"><rect x="1" y="3" width="15" height="13"/><polyline points="16 8 20 8 23 11 23 16 16 16"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/></svg>
                        <span class="text-[9px] font-bold uppercase tracking-wider">Fast USA Shipping</span>
                    </div>
                    <div class="bg-zinc-50 p-4 rounded-2xl border border-border flex flex-col items-center text-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-primary"><path d="M4.5 3h15M6 3v16a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V3M6 14h12"/></svg>
                        <span class="text-[9px] font-bold uppercase tracking-wider">Research Grade</span>
                    </div>
                </div>
            </div>

            <!-- Details Section -->
            <div class="flex flex-col gap-8">
                <div class="space-y-2">
                    <div class="flex items-center gap-3">
                        <span class="bg-primary/10 text-primary text-[10px] font-black px-3 py-1 rounded-full tracking-[0.2em] uppercase">Laboratory Standard</span>
                        <?php if ( $product->is_featured() ) : ?>
                            <span class="bg-secondary/10 text-secondary-foreground text-[10px] font-black px-3 py-1 rounded-full tracking-[0.2em] uppercase">Top Choice</span>
                        <?php endif; ?>
                    </div>
                    <h1 class="text-4xl md:text-5xl font-black tracking-tight text-zinc-900 uppercase leading-[0.9]">
                        <?php the_title(); ?>
                    </h1>
                    <div class="flex items-baseline gap-4">
                        <p class="text-3xl font-black text-primary tracking-tighter">
                            <?php echo $product->get_price_html(); ?>
                        </p>
                    </div>
                </div>

                <div class="prose prose-zinc max-w-none text-zinc-500 leading-relaxed text-lg">
                    <?php the_excerpt(); ?>
                    <p>All Helivex Labs compounds are strictly for laboratory research and development use only. Our 99%+ purity is verified through rigorous third-party testing.</p>
                </div>

                <!-- Product Meta / Scientific Data -->
                <div class="grid grid-cols-2 gap-4 py-6 border-y border-zinc-100">
                    <?php 
                    $cas = get_post_meta($product->get_id(), '_research_cas', true);
                    $formula = get_post_meta($product->get_id(), '_research_formula', true);
                    $batch = get_post_meta($product->get_id(), '_coa_batch', true);
                    $purity = get_post_meta($product->get_id(), '_coa_purity', true);
                    ?>
                    
                    <?php if ($cas): ?>
                    <div class="space-y-1">
                        <p class="text-[10px] font-black text-zinc-400 uppercase tracking-widest">CAS Number</p>
                        <p class="text-sm font-bold text-zinc-900"><?php echo esc_html($cas); ?></p>
                    </div>
                    <?php endif; ?>

                    <?php if ($formula): ?>
                    <div class="space-y-1">
                        <p class="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Formula</p>
                        <p class="text-sm font-bold text-zinc-900"><?php echo esc_html($formula); ?></p>
                    </div>
                    <?php endif; ?>

                    <?php if ($batch): ?>
                    <div class="space-y-1">
                        <p class="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Batch ID</p>
                        <p class="text-sm font-bold text-zinc-900"><?php echo esc_html($batch); ?></p>
                    </div>
                    <?php endif; ?>

                    <?php if ($purity): ?>
                    <div class="space-y-1">
                        <p class="text-[10px] font-black text-zinc-400 uppercase tracking-widest">Purity</p>
                        <p class="text-sm font-bold text-zinc-900"><?php echo esc_html($purity); ?></p>
                    </div>
                    <?php endif; ?>
                </div>

                <div class="space-y-6 pt-4 border-t border-zinc-100 woocommerce-add-to-cart-container">
                    <?php 
                    /**
                     * Output the add to cart form.
                     */
                    woocommerce_template_single_add_to_cart();

                    // Fallback: If the product is not purchasable (e.g. no price set), show a warning for admins
                    if ( current_user_can( 'manage_options' ) && ! $product->is_purchasable() ) {
                        echo '<div class="bg-amber-50 border border-amber-200 p-4 rounded-xl text-amber-800 text-xs font-bold uppercase tracking-widest">';
                        echo 'Admin Notice: This product is missing a price or is not purchasable. "Add to Cart" will not show until a price is set.';
                        echo '</div>';
                    }
                    ?>
                </div>

                <div class="pt-4">
                    <a href="<?php echo esc_url( home_url( '/coa' ) ); ?>" class="w-full flex items-center justify-center gap-2 text-xs font-black tracking-widest text-zinc-400 hover:text-primary transition-colors py-4 border-2 border-dashed border-border rounded-xl hover:border-primary/40">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                        VIEW BATCH ANALYSIS (COA)
                    </a>
                </div>
            </div>
        </div>
        
        <!-- Long Description Section -->
        <div class="mt-20 pt-20 border-t border-zinc-100">
            <div class="max-w-3xl mx-auto">
                <h2 class="text-2xl font-black tracking-tight uppercase mb-8">Technical Specifications</h2>
                <div class="prose prose-zinc max-w-none text-zinc-500 leading-relaxed">
                    <?php the_content(); ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php do_action( 'woocommerce_after_single_product' ); ?>
