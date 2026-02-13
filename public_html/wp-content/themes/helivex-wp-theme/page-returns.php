<?php
/**
 * Template Name: Refund & Returns Policy
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-12">
        <header class="space-y-4 border-b border-zinc-100 pb-8">
            <h1 class="text-4xl font-black tracking-tighter uppercase italic">Refund & Returns Policy</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-sm">Helivex Labs Research Quality Protocol</p>
        </header>

        <section class="prose prose-zinc max-w-none space-y-12">
            
            <!-- Key Policy Summary -->
            <div class="p-8 bg-zinc-50 border border-zinc-100 rounded-3xl space-y-4">
                <h2 class="text-sm font-black uppercase tracking-widest text-zinc-900 m-0">Laboratory Standard Refund Policy</h2>
                <p class="text-sm text-zinc-600 leading-relaxed m-0">
                    At Helivex Labs, we pride ourselves on delivering the best possible experience for the research community. 
                    Due to the sensitive nature of laboratory research materials, we have established strict protocols regarding returns and refunds to ensure the integrity of our supply chain.
                </p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-12">
                <div class="space-y-4">
                    <h3 class="text-xl font-bold uppercase tracking-tight flex items-center gap-2">
                        <span class="w-8 h-8 rounded-full bg-zinc-900 text-white flex items-center justify-center text-xs">01</span>
                        Returns & Restocking
                    </h3>
                    <p class="text-zinc-600 text-sm leading-relaxed">
                        If we accept your return, you will receive a refund minus the shipping charges and a <strong>15% restocking fee</strong>. 
                        Please contact us at <a href="mailto:support@helivexlabs.com" class="text-primary font-bold">support@helivexlabs.com</a> for shipping labels and return information.
                    </p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-bold uppercase tracking-tight flex items-center gap-2">
                        <span class="w-8 h-8 rounded-full bg-zinc-900 text-white flex items-center justify-center text-xs">02</span>
                        Peptide Integrity
                    </h3>
                    <p class="text-zinc-600 text-sm leading-relaxed">
                        <strong>We do not accept returns of peptides</strong> due to possible product degradation. 
                        Once these materials leave our climate-controlled facility, their molecular integrity can no longer be guaranteed to the level required for laboratory standards.
                    </p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-bold uppercase tracking-tight flex items-center gap-2">
                        <span class="w-8 h-8 rounded-full bg-zinc-900 text-white flex items-center justify-center text-xs">03</span>
                        Damaged Goods
                    </h3>
                    <p class="text-zinc-600 text-sm leading-relaxed">
                        We will accept limited returns if a product arrives damaged. Please contact customer service at <a href="mailto:support@helivexlabs.com" class="text-primary font-bold">support@helivexlabs.com</a> within 24 hours of delivery for instructions and replacement protocols.
                    </p>
                </div>

                <div class="space-y-4">
                    <h3 class="text-xl font-bold uppercase tracking-tight flex items-center gap-2">
                        <span class="w-8 h-8 rounded-full bg-zinc-900 text-white flex items-center justify-center text-xs">04</span>
                        Lost Shipments
                    </h3>
                    <p class="text-zinc-600 text-sm leading-relaxed">
                        If a shipment has been lost by the carrier (USPS, UPS, etc.) and is not recovered, and the delivery confirmation report shows a non-delivery, <strong>we will reship at no cost to the customer.</strong>
                    </p>
                </div>
            </div>

            <div class="pt-8 border-t border-zinc-100">
                <div class="space-y-6 text-sm text-zinc-600 leading-relaxed">
                    <p>
                        Helivex Labs products are sold strictly for <strong>Research Use Only (RUO)</strong> and are available exclusively to qualified researchers operating in controlled laboratory environments. 
                        By purchasing from Helivex Labs, you confirm that you are a qualified researcher and will not ingest or topically apply our products.
                    </p>
                    <div class="bg-red-50 border border-red-100 p-6 rounded-2xl">
                        <p class="text-red-900 font-bold uppercase tracking-widest text-[10px] mb-2">Important Disclaimer</p>
                        <p class="text-red-800 text-xs m-0">
                            Helivex Labs will not be held liable for damage caused by a purchaser’s choice to consume or use our products topically. 
                            Any communications indicating use of Helivex Labs materials for other than scientific research purposes will result in refusal of purchases and account deactivation.
                        </p>
                    </div>
                </div>
            </div>
        </section>
    </div>
</main>

<?php get_footer(); ?>
