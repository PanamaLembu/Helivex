<?php
/**
 * Cart Page
 */

defined( 'ABSPATH' ) || exit;

do_action( 'woocommerce_before_cart' ); ?>

<div class="container py-12 max-w-5xl">
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-12">
        
        <!-- Left Column: Order Review -->
        <div class="lg:col-span-7 space-y-12">
            <div>
                <h1 class="text-4xl font-black tracking-tighter mb-2 uppercase italic">Review Your Order</h1>
                <p class="text-zinc-400 font-medium uppercase tracking-widest text-[10px]">Secure Research Portal</p>
            </div>

            <form class="woocommerce-cart-form" action="<?php echo esc_url( wc_get_cart_url() ); ?>" method="post">
                <div class="space-y-6">
                    <div class="flex items-center gap-3">
                        <div class="h-8 w-1 bg-pink-500 rounded-full shadow-[0_0_10px_rgba(236,72,153,0.5)]"></div>
                        <h2 class="text-xl font-bold uppercase tracking-tight">Cart Items</h2>
                    </div>

                    <?php
                    foreach ( WC()->cart->get_cart() as $cart_item_key => $cart_item ) {
                        $_product   = apply_filters( 'woocommerce_cart_item_product', $cart_item['data'], $cart_item, $cart_item_key );
                        $product_id = apply_filters( 'woocommerce_cart_item_product_id', $cart_item['product_id'], $cart_item, $cart_item_key );

                        if ( $_product && $_product->exists() && $cart_item['quantity'] > 0 && apply_filters( 'woocommerce_cart_item_visible', true, $cart_item, $cart_item_key ) ) {
                            $product_permalink = apply_filters( 'woocommerce_cart_item_permalink', $_product->is_visible() ? $_product->get_permalink( $cart_item ) : '', $cart_item, $cart_item_key );
                            ?>
                            <div class="flex items-center gap-6 p-6 bg-white rounded-2xl border border-zinc-100 group relative pink-metallic-glow">
                                <div class="h-20 w-20 bg-zinc-50 rounded-xl border border-zinc-100 p-2 flex-shrink-0">
                                    <?php
                                    $thumbnail = apply_filters( 'woocommerce_cart_item_thumbnail', $_product->get_image(), $cart_item, $cart_item_key );
                                    echo $thumbnail;
                                    ?>
                                </div>
                                
                                <div class="flex-grow">
                                    <h3 class="font-bold text-lg uppercase"><?php echo $_product->get_name(); ?></h3>
                                    <div class="flex items-center gap-4 mt-2">
                                        <span class="text-sm font-medium text-zinc-400 uppercase tracking-widest">QTY: <?php echo $cart_item['quantity']; ?></span>
                                        <span class="text-sm font-bold text-pink-500"><?php echo WC()->cart->get_product_price( $_product ); ?></span>
                                    </div>
                                </div>

                                <?php
                                    echo apply_filters( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                                        'woocommerce_cart_item_remove_link',
                                        sprintf(
                                            '<a href="%s" class="p-2 text-zinc-300 hover:text-pink-500 hover:bg-pink-50 rounded-xl transition-all" aria-label="%s" data-product_id="%s" data-product_sku="%s"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg></a>',
                                            esc_url( wc_get_cart_remove_url( $cart_item_key ) ),
                                            /* translators: %s is the product name */
                                            esc_attr( sprintf( __( 'Remove %s from cart', 'woocommerce' ), $_product->get_name() ) ),
                                            esc_attr( $product_id ),
                                            esc_attr( $_product->get_sku() )
                                        ),
                                        $cart_item_key
                                    );
                                ?>
                            </div>
                            <?php
                        }
                    }
                    ?>
                </div>
                
                <div class="mt-8 flex justify-end">
                    <button type="submit" class="btn-primary" name="update_cart" value="<?php esc_attr_e( 'Update cart', 'woocommerce' ); ?>"><?php esc_html_e( 'Update cart', 'woocommerce' ); ?></button>
                    <?php wp_nonce_field( 'woocommerce-cart', 'woocommerce-cart-nonce' ); ?>
                </div>
            </form>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-12">
                <div class="p-4 rounded-2xl bg-zinc-50 border border-zinc-100 flex items-center gap-4">
                    <div class="h-10 w-10 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-600">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
                    </div>
                    <div>
                        <p class="text-[10px] font-black uppercase tracking-widest text-zinc-400 leading-none mb-1">Authenticity</p>
                        <p class="text-xs font-bold uppercase">99%+ Purity Guaranteed</p>
                    </div>
                </div>
                <div class="p-4 rounded-2xl bg-zinc-50 border border-zinc-100 flex items-center gap-4">
                    <div class="h-10 w-10 rounded-full bg-pink-500/10 flex items-center justify-center text-pink-500">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>
                    </div>
                    <div>
                        <p class="text-[10px] font-black uppercase tracking-widest text-zinc-400 leading-none mb-1">Security</p>
                        <p class="text-xs font-bold uppercase">Secure SSL Encryption</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Right Column: Checkout Summary -->
        <div class="lg:col-span-5">
            <div class="sticky top-24 space-y-6">
                <div class="bg-zinc-900 text-white p-8 rounded-3xl shadow-2xl relative overflow-hidden pink-metallic-glow">
                    <!-- Background Glow -->
                    <div class="absolute top-0 right-0 w-32 h-32 bg-pink-500/20 blur-3xl rounded-full -translate-y-1/2 translate-x-1/2"></div>
                    
                    <h2 class="text-xl font-bold mb-6 relative z-10 uppercase tracking-tighter">Order Summary</h2>
                    
                    <div class="space-y-4 relative z-10">
                        <div class="flex justify-between text-zinc-400 text-sm font-bold uppercase tracking-widest">
                            <span>Subtotal</span>
                            <span><?php wc_cart_totals_subtotal_html(); ?></span>
                        </div>
                        <div class="flex justify-between text-zinc-400 text-sm font-bold uppercase tracking-widest">
                            <span>Shipping</span>
                            <span class="text-emerald-400 text-[10px]">Calculated at Checkout</span>
                        </div>
                        <div class="h-[1px] bg-white/10 my-4"></div>
                        <div class="flex justify-between items-end">
                            <div>
                                <p class="text-[10px] font-black uppercase tracking-[0.2em] text-pink-500">Total Payable</p>
                                <p class="text-4xl font-black tracking-tighter"><?php wc_cart_totals_order_total_html(); ?></p>
                            </div>
                        </div>

                        <div class="wc-proceed-to-checkout mt-8">
                            <?php do_action( 'woocommerce_proceed_to_checkout' ); ?>
                        </div>

                        <div class="mt-8 pt-8 border-t border-white/10 space-y-4">
                            <div class="flex items-center justify-center gap-6 opacity-60 transition-all">
                                <div class="flex items-center gap-2">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-zinc-300"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                                    <span class="text-[10px] font-black tracking-widest uppercase text-zinc-300">Plaid</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-zinc-300"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                                    <span class="text-[10px] font-black tracking-widest uppercase text-zinc-300">Crypto</span>
                                </div>
                            </div>
                            <p class="text-[9px] text-zinc-500 text-center font-bold uppercase tracking-[0.2em]">
                                SECURE HUB: PLAID & CRYPTO ENCRYPTED
                            </p>
                        </div>
                    </div>
                </div>

                <div class="p-6 bg-zinc-50 rounded-2xl border border-zinc-100 border-dashed">
                    <p class="text-[10px] text-zinc-400 leading-relaxed text-center font-bold uppercase tracking-widest opacity-60">
                        Complete your purchase with Plaid or Crypto on our secure payment portal.
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
<?php do_action( 'woocommerce_after_cart' ); ?>
