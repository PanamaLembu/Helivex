<?php
/**
 * Template Name: COA Page
 */

get_header();

// In a real WP setup, we would fetch these from product meta or a custom post type.
// For now, we'll use the data structure from the Next.js version.
$products_query = new WP_Query(array(
    'post_type' => 'product',
    'posts_per_page' => -1,
));

$coas = array();
if ($products_query->have_posts()) {
    while ($products_query->have_posts()) {
        $products_query->the_post();
        $product = wc_get_product(get_the_ID());
        $coa_image = get_post_meta(get_the_ID(), '_coa_image', true);
        
        // Only show products that have a COA image uploaded
        if ($coa_image) {
            $coas[] = array(
                'id' => get_the_ID(),
                'name' => get_the_title(),
                'batch' => get_post_meta(get_the_ID(), '_coa_batch', true) ?: 'PENDING',
                'purity' => get_post_meta(get_the_ID(), '_coa_purity', true) ?: 'N/A',
                'quantity' => get_post_meta(get_the_ID(), '_coa_quantity', true) ?: 'N/A',
                'weight' => get_post_meta(get_the_ID(), '_coa_mass', true) ?: 'N/A',
                'date' => get_post_meta(get_the_ID(), '_coa_date', true) ?: 'N/A',
                'image' => $coa_image
            );
        }
    }
    wp_reset_postdata();
}
?>

<main class="min-h-screen bg-white text-zinc-900 font-sans selection:bg-primary/10">
    <!-- Admin Notice -->
    <?php if (current_user_can('manage_options')) : ?>
        <div class="bg-primary/10 border-b border-primary/20 py-2">
            <div class="max-w-7xl mx-auto px-4 flex justify-between items-center">
                <p class="text-[10px] font-black tracking-widest uppercase text-primary">Admin Mode: Upload COAs in the Product Editor</p>
                <a href="<?php echo admin_url('edit.php?post_type=product'); ?>" class="text-[10px] font-black tracking-widest uppercase bg-primary text-white px-3 py-1 rounded-full">Go to Products</a>
            </div>
        </div>
    <?php endif; ?>
    <!-- Hero Section -->
    <section class="relative py-24 overflow-hidden bg-zinc-50 border-b border-zinc-100 reflective-glow">
        <div class="max-w-7xl mx-auto px-4 relative z-10">
            <div class="flex flex-col md:flex-row md:items-end justify-between gap-8">
                <div class="max-w-2xl">
                    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 mb-6">
                        <span class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>
                        <span class="text-[10px] font-bold tracking-[0.2em] uppercase text-primary">Live Lab Verification</span>
                    </div>
                    <h1 class="text-5xl md:text-7xl font-bold tracking-tighter mb-4 leading-[0.9]">
                        Certificate of <span class="text-primary italic">Analysis.</span>
                    </h1>
                    <p class="text-lg text-zinc-500 leading-relaxed">
                        Total transparency in research. Access the latest HPLC and Mass Spectrometry reports for every batch in our inventory.
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- COA Table Section -->
    <section class="py-12 bg-white">
        <div class="max-w-7xl mx-auto px-4">
            <div class="bg-white rounded-3xl border border-zinc-100 overflow-hidden shadow-sm">
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-zinc-50 border-b border-zinc-100">
                                <th class="px-6 py-4 text-[10px] font-black tracking-widest text-zinc-400 uppercase">Compound</th>
                                <th class="px-6 py-4 text-[10px] font-black tracking-widest text-zinc-400 uppercase">Batch ID</th>
                                <th class="px-6 py-4 text-[10px] font-black tracking-widest text-zinc-400 uppercase">Purity</th>
                                <th class="px-6 py-4 text-[10px] font-black tracking-widest text-zinc-400 uppercase">Date</th>
                                <th class="px-6 py-4 text-right text-[10px] font-black tracking-widest text-zinc-400 uppercase">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-zinc-50">
                            <?php foreach ($coas as $coa) : ?>
                            <tr class="group hover:bg-zinc-50/50 transition-colors">
                                <td class="px-6 py-6">
                                    <div class="flex items-center gap-4">
                                        <div class="w-10 h-10 rounded-xl bg-primary/5 flex items-center justify-center text-primary group-hover:scale-110 transition-transform">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 3h15"/><path d="M6 3v16a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V3"/><path d="M6 14h12"/></svg>
                                        </div>
                                        <div>
                                            <div class="font-bold text-zinc-900"><?php echo esc_html($coa['name']); ?></div>
                                            <div class="text-[10px] text-zinc-400 font-medium"><?php echo esc_html($coa['quantity']); ?></div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-6">
                                    <code class="text-xs font-mono bg-zinc-100 px-2 py-1 rounded text-zinc-600">
                                        <?php echo esc_html($coa['batch']); ?>
                                    </code>
                                </td>
                                <td class="px-6 py-6">
                                    <div class="flex items-center gap-2">
                                        <div class="w-1.5 h-1.5 rounded-full bg-emerald-500"></div>
                                        <span class="font-bold text-zinc-900"><?php echo esc_html($coa['purity']); ?></span>
                                    </div>
                                </td>
                                <td class="px-6 py-6 text-sm text-zinc-500 font-medium">
                                    <?php echo esc_html($coa['date']); ?>
                                </td>
                                <td class="px-6 py-6 text-right">
                                    <button onclick="window.open('<?php echo esc_url($coa['image']); ?>', '_blank')" class="inline-flex items-center gap-2 px-4 py-2 bg-white border border-zinc-200 rounded-xl text-[10px] font-black tracking-widest uppercase text-zinc-900 hover:bg-zinc-50 hover:border-zinc-300 transition-all">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                                        View
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>

    <!-- Purity Standards Section -->
    <section class="py-24 bg-zinc-50">
        <div class="max-w-7xl mx-auto px-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="p-8 bg-white rounded-3xl border border-zinc-100 space-y-4">
                    <div class="w-12 h-12 rounded-2xl bg-primary/5 flex items-center justify-center text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
                    <h3 class="font-bold text-lg">Third-Party Verified</h3>
                    <p class="text-sm text-zinc-500 leading-relaxed">All batches are verified by independent US laboratories using HPLC and Mass Spectrometry.</p>
                </div>
                <div class="p-8 bg-white rounded-3xl border border-zinc-100 space-y-4">
                    <div class="w-12 h-12 rounded-2xl bg-primary/5 flex items-center justify-center text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                    </div>
                    <h3 class="font-bold text-lg">Batch-Specific Data</h3>
                    <p class="text-sm text-zinc-500 leading-relaxed">We don't use generic reports. Every report corresponds to the specific batch you receive.</p>
                </div>
                <div class="p-8 bg-white rounded-3xl border border-zinc-100 space-y-4">
                    <div class="w-12 h-12 rounded-2xl bg-primary/5 flex items-center justify-center text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                    </div>
                    <h3 class="font-bold text-lg">Unmatched Purity</h3>
                    <p class="text-sm text-zinc-500 leading-relaxed">Our compounds consistently test above 99% purity, meeting the highest standards for research.</p>
                </div>
            </div>
        </div>
    </section>
</main>

<?php get_footer(); ?>
