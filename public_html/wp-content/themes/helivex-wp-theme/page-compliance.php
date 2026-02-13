<?php
/**
 * Template Name: RUO Compliance & Standards
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-12">
        <header class="space-y-4">
            <h1 class="text-4xl font-black tracking-tighter uppercase italic">RUO Compliance & Quality Standards</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-sm">Laboratory Protocol & Verification</p>
        </header>

        <section class="prose prose-zinc max-w-none">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
                <div class="p-8 border border-zinc-100 rounded-3xl bg-zinc-50">
                    <h3 class="text-lg font-black uppercase tracking-tight mb-2">99%+ Purity</h3>
                    <p class="text-sm text-zinc-500 italic leading-relaxed">All compounds are synthesized to exceed 99% purity as verified by HPLC and Mass Spectrometry analysis.</p>
                </div>
                <div class="p-8 border border-zinc-100 rounded-3xl bg-zinc-50">
                    <h3 class="text-lg font-black uppercase tracking-tight mb-2">Lyophilization</h3>
                    <p class="text-sm text-zinc-500 italic leading-relaxed">Our peptides are vacuum-sealed and freeze-dried to ensure maximum stability during transit and storage.</p>
                </div>
            </div>

            <h3 class="text-xl font-bold uppercase tracking-tight">1. "For Research Use Only" (RUO)</h3>
            <p>
                In strict adherence to <strong>FDA regulations</strong>, all products provided by Helivex Labs are designated for <strong>in vitro laboratory research use only</strong>. 
                They are not intended for human or animal consumption, nor are they intended for diagnostic or therapeutic use. 
                Purchasers must be affiliated with a recognized research institution or laboratory facility.
            </p>

            <h3 class="text-xl font-bold uppercase tracking-tight">2. Certificates of Analysis (COA)</h3>
            <p>
                Transparency is the cornerstone of our operations. Every batch of peptides we distribute is accompanied by a **Certificate of Analysis**. 
                You can find individual batch details on our <a href="/coa" class="text-primary font-bold underline">COA Archive</a> page. 
                Our testing protocols include:
                <ul>
                    <li><strong>HPLC Analysis:</strong> To determine chemical purity.</li>
                    <li><strong>Mass Spec (MS):</strong> To verify correct molecular weight and identity.</li>
                    <li><strong>Microbial Testing:</strong> To ensure the absence of contaminants.</li>
                </ul>
            </p>

            <h3 class="text-xl font-bold uppercase tracking-tight">3. Secure Handling & Storage</h3>
            <p>
                We maintain a climate-controlled environment for all raw and finished products. 
                Orders are packed in specialized insulated materials when necessary to prevent degradation.
            </p>

            <div class="mt-12 p-8 bg-zinc-900 rounded-3xl text-white">
                <h4 class="text-sm font-black uppercase tracking-[0.2em] text-zinc-400 mb-4 text-center">Underwriting & Compliance Notice</h4>
                <p class="text-xs leading-relaxed text-zinc-300 text-center italic">
                    Helivex Labs operates with full transparency. We do not make health claims, provide dosing instructions, or market our products for human use. 
                    Our business model is strictly B2B/B2R (Business to Research) and complies with all major credit card network high-risk guidelines.
                </p>
            </div>
        </section>
    </div>
</main>

<?php get_footer(); ?>
