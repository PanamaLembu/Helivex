<?php
/**
 * The template for displaying product content within loops
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/content-product.php.
 */

defined( 'ABSPATH' ) || exit;

global $product;

// Ensure visibility.
if ( empty( $product ) || ! $product->is_visible() ) {
    return;
}
?>

<div <?php wc_product_class( 'group flex flex-col bg-white rounded-2xl border border-border overflow-hidden transition-all hover:shadow-xl hover:shadow-primary/5 hover:border-primary/20 pink-metallic-glow', $product ); ?>>
    <!-- Image Section -->
    <a href="<?php the_permalink(); ?>" class="aspect-[4/5] relative bg-zinc-50 overflow-hidden flex items-center justify-center p-8">
        <!-- Subtle Lab Background Pattern -->
        <div class="absolute inset-0 opacity-[0.03] pointer-events-none group-hover:opacity-[0.06] transition-opacity duration-500">
            <div class="absolute top-4 right-4 w-16 h-16 rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
            </div>
            <div class="absolute bottom-6 left-6 w-14 h-14 -rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M7 2h10l2 10H5L7 2z"/><path d="M5 12h14v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-7z"/></svg>
            </div>
        </div>

        <!-- Status Badges -->
        <div class="absolute top-4 left-4 z-10 flex flex-col gap-2">
            <?php if ( $product->is_on_sale() ) : ?>
                <span class="bg-secondary/90 backdrop-blur-sm text-secondary-foreground text-[9px] font-black tracking-widest px-2.5 py-1 rounded-full border border-primary/10 uppercase">SALE</span>
            <?php endif; ?>
            <?php if ( $product->is_featured() ) : ?>
                <span class="bg-primary/90 backdrop-blur-sm text-primary-foreground text-[9px] font-black tracking-widest px-2.5 py-1 rounded-full border border-white/10 uppercase">TOP_RESEARCH</span>
            <?php endif; ?>
        </div>

        <!-- Corner Accent -->
        <div class="absolute top-0 right-0 w-16 h-16 pointer-events-none">
            <div class="absolute top-0 right-0 w-[1px] h-8 bg-primary/20"></div>
            <div class="absolute top-0 right-0 w-8 h-[1px] bg-primary/20"></div>
        </div>
        
        <div class="relative w-full h-full group-hover:scale-110 transition-all duration-700 flex items-center justify-center">
            <?php echo $product->get_image( 'woocommerce_thumbnail', array( 'class' => 'object-contain drop-shadow-2xl' ) ); ?>
        </div>
        
        <div class="absolute inset-0 bg-primary/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none reflective-glow"></div>
    </a>
    
    <!-- Info Section -->
    <div class="p-5 flex flex-col gap-4">
        <div class="space-y-1">
            <a href="<?php the_permalink(); ?>" class="block">
                <h3 class="font-bold text-lg group-hover:text-primary transition-colors"><?php the_title(); ?></h3>
            </a>
            <div class="flex items-center justify-between">
                <p class="text-primary font-black text-sm tracking-tight"><?php echo $product->get_price_html(); ?></p>
            </div>
        </div>

        <a href="<?php the_permalink(); ?>" class="w-full bg-primary text-white text-[10px] font-black tracking-[0.2em] py-3.5 rounded-xl shadow-lg shadow-primary/20 flex items-center justify-center gap-2 group/btn relative overflow-hidden transition-all hover:bg-accent active:scale-[0.98]">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="relative z-10"><path d="M16 3l1.5 1.5M4 19l1.5 1.5M10 5l1.5 1.5M12 12l1.5 1.5M19 4l-4 4M10 10l-6 6M20 10l-4 4M15 5l-2 2"/></svg>
            <span class="relative z-10 uppercase">BUY RESEARCH PEPTIDE</span>
            <div class="absolute inset-0 bg-white/10 translate-y-full group-hover/btn:translate-y-0 transition-transform duration-300"></div>
        </a>
    </div>
</div>
