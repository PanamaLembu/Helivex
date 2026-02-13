<?php
/**
 * Template Name: About Us
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-16">
        <header class="space-y-6 text-center">
            <div class="inline-block px-4 py-1 bg-zinc-100 text-zinc-500 text-[10px] font-black uppercase tracking-[0.3em] rounded-full mb-4">Established 2026</div>
            <h1 class="text-6xl font-black tracking-tighter uppercase italic leading-none">The Science of<br><span class="text-zinc-300">Integrity</span></h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-xs max-w-lg mx-auto leading-relaxed">Dedicated to providing the global scientific community with high-purity research compounds and analytical data.</p>
        </header>

        <section class="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
            <div class="space-y-6">
                <h2 class="text-3xl font-black uppercase tracking-tight italic">Our Laboratory Mission</h2>
                <p class="text-zinc-600 leading-relaxed">
                    Helivex Labs was founded on a singular principle: <strong>Precision</strong>. In the rapidly evolving landscape of peptide research, accuracy in compound synthesis and purity verification is paramount. 
                </p>
                <p class="text-zinc-600 leading-relaxed">
                    We serve as a primary supplier for independent researchers, academic institutions, and private laboratories. Our facility utilizes state-of-the-art HPLC and Mass Spectrometry to ensure every vial meets our rigorous 99%+ purity threshold.
                </p>
            </div>
            <div class="aspect-square bg-zinc-50 border border-zinc-100 rounded-3xl overflow-hidden relative group">
                <img src="<?php echo get_template_directory_uri(); ?>/assets/images/swirl.jpg" alt="Lab Standards" class="w-full h-full object-cover opacity-80 group-hover:opacity-100 transition-opacity">
                <div class="absolute inset-0 flex items-center justify-center p-8 bg-black/10">
                    <div class="text-center space-y-4">
                        <div class="text-4xl font-black italic text-white drop-shadow-lg tracking-tighter uppercase">99%+</div>
                        <p class="text-[10px] font-black uppercase tracking-widest text-white/80 drop-shadow-md">Average Purity Rating</p>
                    </div>
                </div>
            </div>
        </section>

        <section class="border-t border-zinc-100 pt-16 space-y-12">
            <h2 class="text-3xl font-black uppercase tracking-tight italic text-center">Compliance & Transparency</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
                <div class="space-y-4">
                    <div class="w-12 h-12 bg-zinc-900 rounded-2xl flex items-center justify-center mx-auto text-white">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <h3 class="font-bold uppercase tracking-tight">RUO Only</h3>
                    <p class="text-xs text-zinc-500">Strict adherence to Research Use Only labeling and fulfillment protocols.</p>
                </div>
                <div class="space-y-4">
                    <div class="w-12 h-12 bg-zinc-900 rounded-2xl flex items-center justify-center mx-auto text-white">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                    </div>
                    <h3 class="font-bold uppercase tracking-tight">Verified COA</h3>
                    <p class="text-xs text-zinc-500">Publicly accessible analytical data for every batch synthesized.</p>
                </div>
                <div class="space-y-4">
                    <div class="w-12 h-12 bg-zinc-900 rounded-2xl flex items-center justify-center mx-auto text-white">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M2 12h20"/></svg>
                    </div>
                    <h3 class="font-bold uppercase tracking-tight">Secure Supply</h3>
                    <p class="text-xs text-zinc-500">Climate-controlled logistics and vacuum-sealed packaging standards.</p>
                </div>
            </div>
        </section>
    </div>
</main>

<?php get_footer(); ?>
