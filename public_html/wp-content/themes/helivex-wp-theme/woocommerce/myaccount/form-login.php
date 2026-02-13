<?php
/**
 * Login Form
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/myaccount/form-login.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

do_action( 'woocommerce_before_customer_login_form' ); ?>

<div class="container mx-auto px-4 py-16" id="customer_login">
    <div class="max-w-6xl mx-auto">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-16">

            <!-- Login Section -->
            <div class="space-y-8 bg-zinc-50/50 p-8 md:p-12 rounded-3xl border border-zinc-100 shadow-sm">
                <div class="space-y-2">
                    <h2 class="text-3xl font-bold tracking-tight text-zinc-900 uppercase"><?php esc_html_e( 'Login', 'woocommerce' ); ?></h2>
                    <p class="text-zinc-500 text-sm">Welcome back. Enter your credentials to access your research dashboard.</p>
                </div>

                <form class="woocommerce-form woocommerce-form-login login space-y-6" method="post">
                    <?php do_action( 'woocommerce_login_form_start' ); ?>

                    <div class="space-y-2">
                        <label for="username" class="text-[10px] font-bold uppercase tracking-widest text-zinc-400"><?php esc_html_e( 'Username or email address', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
                        <input type="text" class="w-full bg-white border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all" name="username" id="username" autocomplete="username" value="<?php echo ( ! empty( $_POST['username'] ) ) ? esc_attr( wp_unslash( $_POST['username'] ) ) : ''; ?>" />
                    </div>

                    <div class="space-y-2">
                        <label for="password" class="text-[10px] font-bold uppercase tracking-widest text-zinc-400"><?php esc_html_e( 'Password', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
                        <input class="w-full bg-white border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all" type="password" name="password" id="password" autocomplete="current-password" />
                    </div>

                    <?php do_action( 'woocommerce_login_form' ); ?>

                    <div class="flex items-center justify-between">
                        <label class="flex items-center gap-2 cursor-pointer group">
                            <input class="w-4 h-4 rounded border-zinc-300 text-primary focus:ring-primary" name="rememberme" type="checkbox" id="rememberme" value="forever" /> 
                            <span class="text-xs text-zinc-500 group-hover:text-zinc-900 transition-colors"><?php esc_html_e( 'Remember me', 'woocommerce' ); ?></span>
                        </label>
                        <p class="woocommerce-LostPassword lost_password">
                            <a href="<?php echo esc_url( wp_lostpassword_url() ); ?>" class="text-xs text-primary font-medium hover:underline"><?php esc_html_e( 'Lost your password?', 'woocommerce' ); ?></a>
                        </p>
                    </div>

                    <?php wp_nonce_field( 'woocommerce-login', 'woocommerce-login-nonce' ); ?>
                    <button type="submit" class="w-full btn-primary py-4 rounded-xl font-bold tracking-widest uppercase text-xs" name="login" value="<?php esc_attr_e( 'Log in', 'woocommerce' ); ?>"><?php esc_html_e( 'Log in', 'woocommerce' ); ?></button>

                    <?php do_action( 'woocommerce_login_form_end' ); ?>
                </form>
            </div>

            <?php if ( 'yes' === get_option( 'woocommerce_enable_myaccount_registration' ) ) : ?>

            <!-- Registration Section -->
            <div class="space-y-8 p-8 md:p-12">
                <div class="space-y-2">
                    <h2 class="text-3xl font-bold tracking-tight text-zinc-900 uppercase"><?php esc_html_e( 'Register', 'woocommerce' ); ?></h2>
                    <p class="text-zinc-500 text-sm">Create a research account to manage protocols and access COA archives.</p>
                </div>

                <form method="post" class="woocommerce-form woocommerce-form-register register space-y-6" <?php do_action( 'woocommerce_register_form_tag' ); ?> >
                    <?php do_action( 'woocommerce_register_form_start' ); ?>

                    <?php if ( 'no' === get_option( 'woocommerce_registration_generate_username' ) ) : ?>
                        <div class="space-y-2">
                            <label for="reg_username" class="text-[10px] font-bold uppercase tracking-widest text-zinc-400"><?php esc_html_e( 'Username', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
                            <input type="text" class="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all" name="username" id="reg_username" autocomplete="username" value="<?php echo ( ! empty( $_POST['username'] ) ) ? esc_attr( wp_unslash( $_POST['username'] ) ) : ''; ?>" />
                        </div>
                    <?php endif; ?>

                    <div class="space-y-2">
                        <label for="reg_email" class="text-[10px] font-bold uppercase tracking-widest text-zinc-400"><?php esc_html_e( 'Email address', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
                        <input type="email" class="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all" name="email" id="reg_email" autocomplete="email" value="<?php echo ( ! empty( $_POST['email'] ) ) ? esc_attr( wp_unslash( $_POST['email'] ) ) : ''; ?>" />
                    </div>

                    <?php if ( 'no' === get_option( 'woocommerce_registration_generate_password' ) ) : ?>
                        <div class="space-y-2">
                            <label for="reg_password" class="text-[10px] font-bold uppercase tracking-widest text-zinc-400"><?php esc_html_e( 'Password', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
                            <input type="password" class="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 transition-all" name="password" id="reg_password" autocomplete="new-password" />
                        </div>
                    <?php else : ?>
                        <p class="text-xs text-zinc-400 italic"><?php esc_html_e( 'A password will be sent to your email address.', 'woocommerce' ); ?></p>
                    <?php endif; ?>

                    <?php do_action( 'woocommerce_register_form' ); ?>

                    <div class="space-y-4">
                        <p class="text-[10px] text-zinc-400 leading-relaxed uppercase tracking-wider">
                            <?php esc_html_e( 'Your personal data will be used to support your experience throughout this website, to manage access to your account, and for other purposes described in our', 'woocommerce' ); ?> <a href="/privacy-policy" class="text-primary hover:underline"><?php esc_html_e( 'privacy policy', 'woocommerce' ); ?></a>.
                        </p>
                        
                        <?php wp_nonce_field( 'woocommerce-register', 'woocommerce-register-nonce' ); ?>
                        <button type="submit" class="w-full bg-zinc-900 text-white py-4 rounded-xl font-bold tracking-widest uppercase text-xs hover:bg-black transition-colors" name="register" value="<?php esc_attr_e( 'Register', 'woocommerce' ); ?>"><?php esc_html_e( 'Create Account', 'woocommerce' ); ?></button>
                    </div>

                    <?php do_action( 'woocommerce_register_form_end' ); ?>
                </form>
            </div>

            <?php endif; ?>

        </div>
    </div>
</div>

<?php do_action( 'woocommerce_after_customer_login_form' ); ?>
