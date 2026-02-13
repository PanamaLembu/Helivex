<?php
/**
 * Template Name: FAQ Page
 */

get_header();
?>

<main class="min-h-screen bg-white text-zinc-900 font-sans selection:bg-primary/10">
    <!-- Hero Section -->
    <section class="relative py-24 overflow-hidden bg-zinc-50/50 border-b border-zinc-100 reflective-glow">
        <div class="max-w-7xl mx-auto px-4 relative z-10 text-center">
            <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 mb-6">
                <span class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>
                <span class="text-[10px] font-bold tracking-[0.2em] uppercase text-primary">Information Center</span>
            </div>
            <h1 class="text-5xl md:text-7xl font-bold tracking-tighter mb-8 leading-[0.9] uppercase">
                Frequently Asked <span class="text-primary italic">Questions.</span>
            </h1>
            <p class="text-xl text-zinc-500 leading-relaxed max-w-2xl mx-auto">
                Everything you need to know about our research compounds, shipping protocols, and quality standards.
            </p>
        </div>
    </section>

    <!-- FAQ Grid -->
    <section class="py-24 bg-white">
        <div class="max-w-4xl mx-auto px-4 space-y-12">
            <?php
            $faq_categories = [
                'Product Information' => [
                    [
                        'q' => 'What are the products from Helivex Labs intended for?',
                        'a' => 'All items sold by Helivex Labs are strictly for laboratory research use only. They are not for human or animal consumption, not for therapeutic use, and not cleared for incorporation into food, cosmetics, medical devices, or drugs.'
                    ],
                    [
                        'q' => 'Do you provide Certificates of Analysis (COAs)?',
                        'a' => 'Yes. Certificates of Analysis are available for every product batch. We ensure 99% purity through rigorous third-party testing to provide the highest quality research peptides online.'
                    ],
                    [
                        'q' => 'How should I store my research peptides?',
                        'a' => 'For long-term stability, lyophilized peptides should be stored at -20°C or -80°C. For short-term use, refrigeration at 4°C is acceptable. Always keep vials away from direct UV light.'
                    ]
                ],
                'Shipping & Orders' => [
                    [
                        'q' => 'What is your shipping time?',
                        'a' => 'Orders are processed quickly and shipped from the USA. You can expect delivery within 3-5 business days from the day you receive your tracking info.'
                    ],
                    [
                        'q' => 'Do you ship internationally?',
                        'a' => 'Currently, we focus on providing reliable service within the United States to ensure the fastest delivery and most consistent quality control.'
                    ],
                    [
                        'q' => 'What payment methods do you accept?',
                        'a' => 'We accept secure payments via Payrio (Credit/Debit cards) and various cryptocurrencies for your convenience and security.'
                    ]
                ]
            ];

            foreach ($faq_categories as $category => $items): ?>
                <div class="space-y-6">
                    <h2 class="text-xs font-black tracking-[0.3em] uppercase text-primary/60 border-b border-zinc-100 pb-4"><?php echo $category; ?></h2>
                    <div class="grid gap-4">
                        <?php foreach ($items as $item): ?>
                            <div class="p-8 rounded-3xl bg-zinc-50/50 border border-zinc-100 hover:border-primary/20 transition-all group">
                                <h3 class="font-bold text-lg mb-4 group-hover:text-primary transition-colors"><?php echo $item['q']; ?></h3>
                                <p class="text-zinc-500 leading-relaxed text-sm"><?php echo $item['a']; ?></p>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </section>

    <!-- Still Have Questions -->
    <section class="py-24 bg-zinc-900 text-white overflow-hidden relative">
        <div class="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_50%_50%,rgba(158,27,27,0.3),transparent)]"></div>
        <div class="max-w-7xl mx-auto px-4 text-center relative z-10">
            <h2 class="text-4xl font-bold tracking-tight mb-6">Still have questions?</h2>
            <p class="text-zinc-400 mb-10 max-w-xl mx-auto">Our scientific support team is ready to assist you with any technical inquiries or order assistance.</p>
            <a href="<?php echo esc_url( home_url( '/contact' ) ); ?>" class="inline-flex items-center gap-2 px-8 py-4 bg-primary text-white text-xs font-black tracking-widest uppercase rounded-xl hover:bg-accent transition-all shadow-xl shadow-primary/20">
                Contact Our Lab
            </a>
        </div>
    </section>
</main>

<?php get_footer(); ?>
