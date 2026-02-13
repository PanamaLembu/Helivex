<?php
/**
 * Checkout Form
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

do_action( 'woocommerce_before_checkout_form', $checkout );

// If checkout registration is disabled and not logged in, the user cannot checkout.
if ( ! $checkout->is_registration_enabled() && $checkout->is_registration_required() && ! is_user_logged_in() ) {
	echo esc_html( apply_filters( 'woocommerce_checkout_must_be_logged_in_message', __( 'You must be logged in to checkout.', 'woocommerce' ) ) );
	return;
}

?>

<div class="container py-12 max-w-7xl mx-auto px-4">
    <h1 class="text-4xl font-black tracking-tighter mb-12 uppercase italic">Secure Checkout</h1>

    <form name="checkout" method="post" class="checkout woocommerce-checkout grid grid-cols-1 lg:grid-cols-12 gap-12" action="<?php echo esc_url( wc_get_checkout_url() ); ?>" enctype="multipart/form-data">

        <?php if ( $checkout->get_checkout_fields() ) : ?>

            <div class="lg:col-span-7 space-y-12" id="customer_details">
                <div class="bg-white p-8 rounded-3xl border border-zinc-100 pink-metallic-glow">
                    <?php do_action( 'woocommerce_checkout_billing' ); ?>
                    <?php do_action( 'woocommerce_checkout_shipping' ); ?>
                </div>
            </div>

        <?php endif; ?>

        <div class="lg:col-span-5">
            <div class="sticky top-24 space-y-6">
                <div id="order_review" class="woocommerce-checkout-review-order bg-zinc-900 text-white p-8 rounded-3xl shadow-2xl relative overflow-hidden pink-metallic-glow">
                    <!-- Background Glow -->
                    <div class="absolute top-0 right-0 w-32 h-32 bg-pink-500/20 blur-3xl rounded-full -translate-y-1/2 translate-x-1/2"></div>
                    
                    <h3 id="order_review_heading" class="text-xl font-bold mb-6 relative z-10 uppercase tracking-tighter"><?php esc_html_e( 'Your order', 'woocommerce' ); ?></h3>
                    
                    <div class="relative z-10">
                        <?php do_action( 'woocommerce_checkout_order_review' ); ?>
                    </div>
                </div>

                <div class="p-6 bg-zinc-50 rounded-2xl border border-zinc-100 border-dashed">
                    <p class="text-[10px] text-zinc-400 leading-relaxed text-center font-bold uppercase tracking-widest opacity-60">
                        Secure research portal. All data is encrypted using 256-bit SSL.
                    </p>
                </div>
            </div>
        </div>

    </form>
</div>

<?php do_action( 'woocommerce_after_checkout_form', $checkout ); ?>
