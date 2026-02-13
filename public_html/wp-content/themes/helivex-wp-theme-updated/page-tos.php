<?php
/**
 * Template Name: Terms of Service
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-12">
        <header class="space-y-4 text-center">
            <div class="inline-block px-4 py-1 bg-red-600 text-white text-[10px] font-black uppercase tracking-[0.3em] rounded-full mb-4">Strict Compliance</div>
            <h1 class="text-5xl font-black tracking-tighter uppercase italic leading-none">Terms of Service</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-xs">By accessing this site, you agree to these binding terms.</p>
        </header>

        <section class="prose prose-zinc max-w-none border-t border-zinc-100 pt-12">
            <div class="bg-red-50 border border-red-100 p-8 rounded-3xl mb-12">
                <h2 class="text-red-900 text-lg font-black uppercase tracking-tight mb-4 italic underline decoration-2 underline-offset-4">CRITICAL: Research Use Only (RUO) Disclaimer</h2>
                <p class="text-red-800 text-sm font-bold leading-relaxed">
                    HELIVEX LABS PRODUCTS ARE INTENDED FOR LABORATORY RESEARCH USE ONLY. 
                    They are NOT for human or veterinary use, including but not limited to, food, drugs, medical devices, or cosmetics. 
                    These products are NOT FDA-approved. You warrant that you are a qualified researcher and will not use these products for human consumption.
                </p>
            </div>

            <div class="space-y-10">
                <div class="space-y-4">
                    <h3 class="text-xl font-black uppercase tracking-tight text-zinc-900">1. Age & Eligibility</h3>
                    <p class="text-zinc-600">You must be at least 18 years of age (or the age of majority in your jurisdiction) to purchase from Helivex Labs. Use of the site constitutes a representation that you meet these age requirements.</p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-black uppercase tracking-tight text-zinc-900">2. ACH (NACHA) & Payment Terms</h3>
                    <p class="text-zinc-600">
                        When using ACH payments via <strong>Plaid</strong>, you authorize a one-time or recurring (if selected) WEB debit from your bank account. 
                        We utilize <strong>Signal risk scoring</strong> to monitor and prevent fraudulent transactions. 
                        You agree to maintain sufficient funds for all authorized transfers.
                    </p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-black uppercase tracking-tight text-zinc-900">3. High-Risk Processing & Fraud</h3>
                    <p class="text-zinc-600">
                        We utilize high-risk credit card processing with integrated <strong>3D Secure (3DS)</strong> and <strong>CVV verification</strong>. 
                        Fraudulent chargebacks will be reported to the appropriate authorities and may result in permanent blacklisting from our services.
                    </p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-black uppercase tracking-tight text-zinc-900">4. Limitation of Liability & Arbitration</h3>
                    <p class="text-zinc-600">
                        Helivex Labs shall not be liable for any damages arising from the misuse of RUO products. 
                        Any disputes arising under these terms shall be resolved through binding individual arbitration in accordance with US consumer data laws.
                    </p>
                </div>
            </div>
        </section>
    </div>
</main>

<?php get_footer(); ?>
