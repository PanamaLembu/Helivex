<?php get_header(); ?>

<div class="flex flex-col relative">
    <!-- Global Background Glows -->
    <div class="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div class="absolute top-[10%] -left-[10%] w-[40%] h-[40%] bg-secondary/10 blur-[120px] rounded-full"></div>
        <div class="absolute bottom-[20%] -right-[10%] w-[50%] h-[50%] bg-secondary/5 blur-[150px] rounded-full"></div>
    </div>

    <!-- Hero Section -->
    <section class="relative h-[80vh] flex items-center overflow-hidden bg-white reflective-glow pink-metallic-glow">
        <!-- Animated Lab Background -->
        <div class="absolute inset-0 z-0 overflow-hidden">
            <!-- Background Image -->
            <div class="absolute inset-0 z-0">
                <img src="<?php echo get_template_directory_uri(); ?>/assets/images/freezervials.jpg" 
                     alt="Advanced Peptide Research Laboratory" 
                     class="w-full h-full object-cover opacity-20">
            </div>
            
            <div class="absolute inset-0 bg-gradient-to-r from-white via-white/80 to-transparent z-10"></div>
            
            <!-- Subtle Molecule Patterns -->
            <div class="absolute top-20 right-[10%] w-64 h-64 text-primary opacity-[0.03] animate-pulse">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" /><path d="M12 7v10" /><path d="m5.8 17.2 4.9-4.2" /><path d="m18.2 17.2-4.9-4.2" />
                </svg>
            </div>
            <div class="absolute bottom-20 right-[25%] w-48 h-48 text-primary opacity-[0.02] rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6 18h8" /><path d="M3 22h18" /><path d="M14 22a7 7 0 1 0 0-14h-1" /><path d="M9 14h2" /><path d="M9 12a2 2 0 1 1-4 0V7a2 2 0 1 1 4 0v5Z" /><path d="M12 7V3a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4" />
                </svg>
            </div>
            <div class="absolute top-[40%] right-[5%] w-32 h-32 text-primary opacity-[0.03] -rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M7 2h10" /><path d="M10 2v18a2 2 0 0 0 4 0V2" /><path d="M10 11h4" /><path d="M10 16h4" />
                </svg>
            </div>
        </div>
        
        <div class="container relative z-10 text-zinc-900">
            <div class="max-w-2xl space-y-8">
                <h1 class="text-4xl sm:text-6xl md:text-8xl font-black tracking-tighter leading-[0.85] text-zinc-900">
                    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/5 border border-primary/10 text-[10px] font-black tracking-widest text-primary uppercase mb-6">
                        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                        <span><?php ehvx('hero_badge', 'ISO 9001:2015 Certified Sourcing'); ?></span>
                    </div><br />
                    <?php ehvx('hero_heading_line1', 'PRECISION IN'); ?> <br />
                    <span class="text-primary italic"><?php ehvx('hero_heading_line2', 'RESEARCH.'); ?></span>
                </h1>
                <p class="text-lg md:text-xl text-zinc-500 max-w-lg leading-relaxed">
                    <?php ehvx('hero_description', 'Helivex Labs provides the scientific community with ultra-pure peptides and research compounds, setting the gold standard for integrity and reliability.'); ?>
                </p>
                <div class="flex flex-wrap gap-4 pt-4">
                    <a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="btn-primary flex items-center gap-2 group px-8 py-4 text-sm font-black tracking-widest">
                        <?php ehvx('hero_cta_primary', 'SHOP RESEARCH PEPTIDES'); ?>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="transition-transform group-hover:translate-x-1"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                    </a>
                    <a href="<?php echo esc_url( home_url( '/about' ) ); ?>" class="px-8 py-4 border border-black/5 rounded-md text-sm font-black tracking-widest hover:bg-black/5 transition-colors">
                        <?php ehvx('hero_cta_secondary', 'ABOUT OUR STANDARDS'); ?>
                    </a>
                </div>
            </div>
        </div>

        <div class="absolute bottom-10 left-1/2 -translate-x-1/2 animate-bounce">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-black/20"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
    </section>

    <!-- Mission Statement Section -->
    <section class="py-10 md:py-12 text-primary-foreground relative z-20"
             style="background: linear-gradient(135deg, var(--primary) 0%, rgba(244, 167, 167, 0.4) 100%);">
        <div class="absolute inset-0 opacity-[0.05] pointer-events-none overflow-hidden">
            <div class="absolute -right-20 -top-20 w-[600px] h-[600px] rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" /><path d="M12 7v10" /><path d="m5.8 17.2 4.9-4.2" /><path d="m18.2 17.2-4.9-4.2" />
                </svg>
            </div>
            <div class="absolute -left-20 -bottom-20 w-[400px] h-[400px] -rotate-12">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                </svg>
            </div>
        </div>
        <div class="container relative z-10 text-center flex flex-col items-center">
            <div class="max-w-3xl space-y-6">
                <h2 class="text-3xl md:text-5xl font-bold tracking-tight uppercase"><?php ehvx('mission_heading', '99%+ Pure Research Standards'); ?></h2>
                <p class="text-lg md:text-2xl leading-relaxed text-primary-foreground/90 font-medium px-4 md:px-0 italic">
                    "<?php ehvx('mission_quote', 'Precision is not just a goal; it is our baseline protocol.'); ?>"
                </p>
                <p class="text-base md:text-lg text-primary-foreground/80 px-4 md:px-0">
                    <?php ehvx('mission_description', 'At Helivex Labs, our purpose is to deliver research peptides at fair, transparent prices. We are built on a foundation of trust, integrity, and uncompromising standards.'); ?>
                </p>
                <div class="pt-2">
                    <a href="<?php echo esc_url( home_url( '/about' ) ); ?>" class="bg-secondary text-secondary-foreground px-6 py-2.5 rounded-full font-bold tracking-widest text-[10px] hover:bg-white hover:text-primary transition-all duration-300 shadow-xl inline-block">
                        <?php ehvx('mission_cta', 'ABOUT OUR STANDARDS'); ?>
                    </a>
                </div>
            </div>
        </div>
    </section>

    <!-- Trust Badges -->
    <section class="py-12 border-b border-border bg-muted/50 pink-metallic-glow">
        <div class="container">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="flex items-center gap-4 p-6 bg-white rounded-lg shadow-sm">
                    <div class="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 11 12 14 15 11"/></svg>
                    </div>
                    <div>
                        <h3 class="font-bold"><?php ehvx('trust_badge_1_title', '99% PURE & TESTED'); ?></h3>
                        <p class="text-sm text-muted-foreground"><?php ehvx('trust_badge_1_desc', 'Rigorous third-party testing.'); ?></p>
                    </div>
                </div>
                <div class="flex items-center gap-4 p-6 bg-white rounded-lg shadow-sm">
                    <div class="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    </div>
                    <div>
                        <h3 class="font-bold"><?php ehvx('trust_badge_2_title', 'SHIPS IN 3-5 DAYS'); ?></h3>
                        <p class="text-sm text-muted-foreground"><?php ehvx('trust_badge_2_desc', 'Fast, reliable USA shipping.'); ?></p>
                    </div>
                </div>
                <div class="flex items-center gap-4 p-6 bg-white rounded-lg shadow-sm">
                    <div class="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary relative overflow-hidden p-2.5">
                        <img src="<?php echo get_template_directory_uri(); ?>/assets/images/helivex-vial-red.png" alt="99% Pure Research Peptides" class="w-full h-full object-contain">
                    </div>
                    <div>
                        <h3 class="font-bold"><?php ehvx('trust_badge_3_title', 'RESEARCH USE ONLY'); ?></h3>
                        <p class="text-sm text-muted-foreground"><?php ehvx('trust_badge_3_desc', 'For laboratory and scientific use.'); ?></p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Featured Products -->
    <section class="py-24 bg-zinc-50/50 relative reflective-glow pink-metallic-glow">
        <div class="container">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-16 gap-4">
                <div class="space-y-2">
                    <div class="flex items-center gap-2 text-primary font-bold text-[10px] tracking-[0.3em] uppercase">
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
                        <span><?php ehvx('featured_label', 'Product Catalog'); ?></span>
                    </div>
                    <h2 class="text-4xl font-bold tracking-tight"><?php ehvx('featured_heading', 'FEATURED COMPOUNDS'); ?></h2>
                    <p class="text-muted-foreground"><?php ehvx('featured_description', 'Precision-engineered research materials for clinical study.'); ?></p>
                </div>
                <a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="btn-primary flex items-center gap-2 group text-sm py-2.5">
                    <?php ehvx('featured_cta', 'SHOP ALL RESEARCH PEPTIDES'); ?>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="transition-transform group-hover:translate-x-1"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </a>
            </div>
            
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
                <?php
                if ( ! class_exists( 'WooCommerce' ) ) {
                    echo '<p class="col-span-full text-center text-primary font-bold">Error: WooCommerce is not active.</p>';
                } else {
                    $args = array(
                        'post_type'      => 'product',
                        'posts_per_page' => 4,
                        'orderby'        => 'date',
                        'order'          => 'DESC'
                    );
                    
                    $loop = new WP_Query( $args );
                    if ( $loop->have_posts() ) {
                        while ( $loop->have_posts() ) : $loop->the_post();
                            wc_get_template_part( 'content', 'product' );
                        endwhile;
                        wp_reset_postdata();
                    } else {
                        ?>
                        <div class="col-span-full py-12 text-center space-y-4">
                            <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-primary/5 text-primary mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                            </div>
                            <h3 class="text-xl font-bold">No Research Compounds Found</h3>
                            <p class="text-muted-foreground max-w-md mx-auto">Please ensure products have been added to the WooCommerce catalog in the admin panel.</p>
                            <?php if ( current_user_can('manage_options') ) : ?>
                                <a href="<?php echo admin_url('post-new.php?post_type=product'); ?>" class="inline-block px-6 py-2 bg-primary text-white rounded-full font-black text-[10px] tracking-widest uppercase mt-4">Add First Product</a>
                            <?php endif; ?>
                        </div>
                        <?php
                    }
                }
                ?>
            </div>
        </div>
    </section>

    <!-- Big Vial Feature Section -->
    <section class="py-32 bg-white overflow-hidden relative reflective-glow pink-metallic-glow">
        <div class="container relative z-10">
            <div class="flex flex-col items-center text-center mb-20 space-y-4">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/5 border border-primary/10 text-[10px] font-black tracking-widest text-primary uppercase">
                    <span><?php ehvx('vial_section_badge', 'Structural Analysis'); ?></span>
                </div>
                <h2 class="text-5xl md:text-7xl font-black tracking-tighter"><?php ehvx('vial_section_heading_1', 'MOLECULAR'); ?> <span class="text-primary italic"><?php ehvx('vial_section_heading_2', 'INTEGRITY.'); ?></span></h2>
            </div>

            <div class="relative max-w-4xl mx-auto flex items-center justify-center min-h-[450px] md:min-h-[600px]">
                <!-- Decorative Rings -->
                <div class="absolute inset-0 border border-black/[0.03] rounded-full scale-110 md:scale-125"></div>
                <div class="absolute inset-0 border border-primary/5 rounded-full scale-125 md:scale-150 animate-pulse"></div>
                
                <!-- The Big Vial -->
                <div id="vial-container" class="relative w-[260px] sm:w-72 md:w-[420px] cursor-crosshair">
                    <!-- Tilted Vial Image -->
                    <img src="<?php echo get_template_directory_uri(); ?>/assets/images/helivex-vial-red.png" 
                         alt="Helivex Research Vial" 
                         class="w-full h-auto drop-shadow-[0_20px_60px_rgba(0,0,0,0.25)] transform rotate-[12deg] hover:rotate-[8deg] transition-transform duration-1000">
                    
                    <!-- Interaction Triggers & Text Boxes -->
                    <?php
                    $saved_positions = get_option('helivex_vial_dot_positions', [
                        'dot1' => ['top' => '12%', 'left' => '48%'],
                        'dot2' => ['top' => '48%', 'left' => '78%'],
                        'dot3' => ['top' => '82%', 'left' => '38%']
                    ]);
                    ?>
                    
                    <!-- Trigger 1: Purity (Top - Near Cap) -->
                    <div id="dot1" class="vial-dot absolute group/dot1 z-30 -translate-x-1/2 -translate-y-1/2" style="top: <?php echo $saved_positions['dot1']['top']; ?>; left: <?php echo $saved_positions['dot1']['left']; ?>;">
                        <div class="relative">
                            <div class="w-5 h-5 bg-primary rounded-full animate-ping absolute inset-0 opacity-40"></div>
                            <div class="w-5 h-5 bg-primary rounded-full relative border-2 border-white shadow-lg cursor-pointer"></div>
                            
                            <!-- Box 1 -->
                            <div class="absolute bottom-full left-1/2 -translate-x-1/2 mb-8 w-64 p-5 bg-white/95 backdrop-blur-md border border-black/5 rounded-2xl shadow-2xl opacity-0 scale-90 pointer-events-none group-hover/dot1:opacity-100 group-hover/dot1:scale-100 group-hover/dot1:pointer-events-auto transition-all duration-300">
                                <div class="text-[9px] font-black text-primary uppercase tracking-[0.2em] mb-1.5"><?php ehvx('vial_dot1_label', 'Purity Level'); ?></div>
                                <div class="text-[13px] text-zinc-600 leading-relaxed font-medium"><?php ehvx('vial_dot1_text', '99%+ Pure Research Grade Peptide, verified by third-party HPLC testing.'); ?></div>
                                <div class="text-[9px] mt-2 text-zinc-400 italic"><?php ehvx('vial_dot1_note', 'Note: Analysis reflects sample COA qualities.'); ?></div>
                                <div class="absolute top-full left-1/2 -translate-x-1/2 w-0 h-0 border-l-[10px] border-l-transparent border-r-[10px] border-r-transparent border-t-[10px] border-t-white/95"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Trigger 2: Vacuum (Middle - Body) -->
                    <div id="dot2" class="vial-dot absolute group/dot2 z-30 -translate-x-1/2 -translate-y-1/2" style="top: <?php echo $saved_positions['dot2']['top']; ?>; left: <?php echo $saved_positions['dot2']['left']; ?>;">
                        <div class="relative">
                            <div class="w-5 h-5 bg-primary rounded-full animate-ping absolute inset-0 opacity-40"></div>
                            <div class="w-5 h-5 bg-primary rounded-full relative border-2 border-white shadow-lg cursor-pointer"></div>
                            
                            <!-- Box 2 -->
                            <div class="absolute top-1/2 left-full ml-8 -translate-y-1/2 w-64 p-5 bg-white/95 backdrop-blur-md border border-black/5 rounded-2xl shadow-2xl opacity-0 scale-90 pointer-events-none group-hover/dot2:opacity-100 group-hover/dot2:scale-100 group-hover/dot2:pointer-events-auto transition-all duration-300">
                                <div class="text-[9px] font-black text-primary uppercase tracking-[0.2em] mb-1.5"><?php ehvx('vial_dot2_label', 'Vacuum Sealed'); ?></div>
                                <div class="text-[13px] text-zinc-600 leading-relaxed font-medium"><?php ehvx('vial_dot2_text', 'Lyophilized powder stored under nitrogen for maximum stability and shelf-life.'); ?></div>
                                <div class="absolute right-full top-1/2 -translate-y-1/2 w-0 h-0 border-t-[10px] border-t-transparent border-b-[10px] border-b-transparent border-r-[10px] border-r-white/95"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Trigger 3: Cold Storage (Bottom - Base) -->
                    <div id="dot3" class="vial-dot absolute group/dot3 z-30 -translate-x-1/2 -translate-y-1/2" style="top: <?php echo $saved_positions['dot3']['top']; ?>; left: <?php echo $saved_positions['dot3']['left']; ?>;">
                        <div class="relative">
                            <div class="w-5 h-5 bg-primary rounded-full animate-ping absolute inset-0 opacity-40"></div>
                            <div class="w-5 h-5 bg-primary rounded-full relative border-2 border-white shadow-lg cursor-pointer"></div>
                            
                            <!-- Box 3 -->
                            <div class="absolute top-full left-1/2 -translate-x-1/2 mt-8 w-64 p-5 bg-white/95 backdrop-blur-md border border-black/5 rounded-2xl shadow-2xl opacity-0 scale-90 pointer-events-none group-hover/dot3:opacity-100 group-hover/dot3:scale-100 group-hover/dot3:pointer-events-auto transition-all duration-300">
                                <div class="text-[9px] font-black text-primary uppercase tracking-[0.2em] mb-1.5"><?php ehvx('vial_dot3_label', 'Cold Storage'); ?></div>
                                <div class="text-[13px] text-zinc-600 leading-relaxed font-medium"><?php ehvx('vial_dot3_text', 'Ships in temperature-controlled packaging to maintain molecular chain integrity.'); ?></div>
                                <div class="absolute bottom-full left-1/2 -translate-x-1/2 w-0 h-0 border-l-[10px] border-l-transparent border-r-[10px] border-r-transparent border-b-[10px] border-b-white/95"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Admin HUD Controls -->
                <?php if (current_user_can('manage_options')) : ?>
                <div class="absolute bottom-[-60px] left-1/2 -translate-x-1/2 flex items-center gap-4 z-50">
                    <button id="edit-hud-toggle" class="p-3 bg-zinc-900 text-white rounded-full shadow-xl hover:bg-primary transition-colors group" title="Edit HUD Positions">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="group-hover:rotate-12 transition-transform"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    <button id="save-hud-positions" class="hidden px-6 py-2.5 bg-primary text-white rounded-full font-black text-[10px] tracking-widest uppercase shadow-xl hover:scale-105 active:scale-95 transition-all">
                        Save Permanent Changes
                    </button>
                </div>

                <script>
                jQuery(document).ready(function($) {
                    let isEditing = false;
                    const $dots = $('.vial-dot');
                    const $container = $('#vial-container');
                    const $saveBtn = $('#save-hud-positions');

                    $('#edit-hud-toggle').click(function() {
                        isEditing = !isEditing;
                        $(this).toggleClass('bg-primary bg-zinc-900');
                        $saveBtn.toggleClass('hidden');
                        
                        if (isEditing) {
                            $dots.addClass('cursor-move ring-4 ring-primary/20').css('pointer-events', 'auto');
                            $('.group\\/dot1, .group\\/dot2, .group\\/dot3').find('> div > div:last-child').addClass('!hidden'); // Hide tooltips while editing
                            makeDraggable();
                        } else {
                            $dots.removeClass('cursor-move ring-4 ring-primary/20');
                            $('.group\\/dot1, .group\\/dot2, .group\\/dot3').find('> div > div:last-child').removeClass('!hidden');
                            location.reload(); // Reset to saved state
                        }
                    });

                    function makeDraggable() {
                        $dots.on('mousedown', function(e) {
                            if (!isEditing) return;
                            const $dot = $(this);
                            const containerRect = $container[0].getBoundingClientRect();
                            
                            $(document).on('mousemove.hudEdit', function(e) {
                                let x = e.clientX - containerRect.left;
                                let y = e.clientY - containerRect.top;
                                
                                // Convert to percentage
                                let xPercent = (x / containerRect.width) * 100;
                                let yPercent = (y / containerRect.height) * 100;
                                
                                // Constrain
                                xPercent = Math.max(0, Math.min(100, xPercent));
                                yPercent = Math.max(0, Math.min(100, yPercent));
                                
                                $dot.css({
                                    top: yPercent + '%',
                                    left: xPercent + '%'
                                });
                            });

                            $(document).one('mouseup', function() {
                                $(document).off('mousemove.hudEdit');
                            });
                        });
                    }

                    $saveBtn.click(function() {
                        const positions = {
                            dot1: { top: $('#dot1').css('top'), left: $('#dot1').css('left') },
                            dot2: { top: $('#dot2').css('top'), left: $('#dot2').css('left') },
                            dot3: { top: $('#dot3').css('top'), left: $('#dot3').css('left') }
                        };

                        $saveBtn.text('Saving...').prop('disabled', true);

                        $.ajax({
                            url: '<?php echo admin_url('admin-ajax.php'); ?>',
                            type: 'POST',
                            data: {
                                action: 'save_vial_dots',
                                positions: positions
                            },
                            success: function(response) {
                                if (response.success) {
                                    $saveBtn.text('SAVED!').addClass('bg-green-500');
                                    setTimeout(() => {
                                        location.reload();
                                    }, 1000);
                                } else {
                                    alert('Error saving positions');
                                    $saveBtn.text('Save Permanent Changes').prop('disabled', false);
                                }
                            }
                        });
                    });
                });
                </script>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <!-- FAQ Section -->
    <section class="py-24 bg-white overflow-hidden relative reflective-glow pink-metallic-glow">
        <div class="container relative z-10">
            <div class="max-w-4xl mx-auto space-y-8">
                <h2 class="text-3xl font-bold tracking-tight text-center mb-12 uppercase"><?php ehvx('home_faq_heading', 'FREQUENTLY ASKED QUESTIONS'); ?></h2>
                <div class="space-y-6">
                    <?php
                    $faqs = [
                        [
                            "q" => hvx('home_faq_1_q', "What are the products from Helivex Labs intended for?"),
                            "a" => hvx('home_faq_1_a', "All items sold by Helivex Labs are strictly for laboratory research use only. They are not for human or animal consumption, not for therapeutic use, and not cleared for incorporation into food, cosmetics, medical devices, or drugs.")
                        ],
                        [
                            "q" => hvx('home_faq_2_q', "Do you provide Certificates of Analysis (COAs)?"),
                            "a" => hvx('home_faq_2_a', "Yes. Certificates of Analysis are available for most products. We ensure 99% purity through rigorous third-party testing to provide the highest quality research peptides online.")
                        ],
                        [
                            "q" => hvx('home_faq_3_q', "What is your shipping time?"),
                            "a" => hvx('home_faq_3_a', "Orders are processed quickly and shipped from the USA. You can expect delivery within 3-5 business days from the day you receive your tracking info. We provide fast, reliable peptide research supplies to your laboratory.")
                        ],
                        [
                            "q" => hvx('home_faq_4_q', "How can I buy peptides online safely?"),
                            "a" => hvx('home_faq_4_a', "When you buy research peptides online from Helivex Labs, you are guaranteed 99% purity, secure encrypted transactions, and discrete, fast USA shipping. All our compounds undergo strict quality control.")
                        ]
                    ];
                    foreach ($faqs as $faq): ?>
                        <div class="p-8 rounded-2xl bg-white border border-zinc-100 shadow-[0_10px_30px_rgba(0,0,0,0.02)] hover:shadow-[0_15px_40px_rgba(0,0,0,0.04)] transition-all duration-300">
                            <h4 class="font-bold text-lg mb-4 text-zinc-900 leading-tight"><?php echo $faq['q']; ?></h4>
                            <p class="text-zinc-500 text-sm leading-relaxed"><?php echo $faq['a']; ?></p>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": [
                <?php foreach ($faqs as $i => $faq): ?>
                {
                    "@type": "Question",
                    "name": "<?php echo esc_js($faq['q']); ?>",
                    "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "<?php echo esc_js($faq['a']); ?>"
                    }
                }<?php echo ($i < count($faqs) - 1) ? ',' : ''; ?>
                <?php endforeach; ?>
            ]
        }
        </script>
    </section>

    <!-- Molecular Analysis Core (HUD Scanner) -->
    <section class="mt-32 md:mt-20 py-32 bg-white overflow-hidden relative">
        <div class="container relative z-10 mx-auto">
            <div class="flex flex-col lg:flex-row gap-20 items-center">
                <!-- Left Side: Visual Analysis Core -->
                <div class="w-full lg:w-1/2 relative aspect-square max-w-[550px]">
                    <!-- HUD Background Text -->
                    <div class="absolute inset-0 flex items-center justify-center opacity-[0.02] pointer-events-none select-none font-mono text-[100px] font-black">
                        CORE_01
                    </div>
                    
                    <!-- HUD Rings -->
                    <div class="absolute inset-0 border border-black/5 rounded-full"></div>
                    <div class="absolute inset-4 border border-primary/10 rounded-full border-dashed animate-spin-slow"></div>
                    <div class="absolute inset-12 border-2 border-black/5 rounded-full border-dotted animate-spin-reverse"></div>
                    
                    <!-- Scanning Laser -->
                    <div class="absolute inset-0 bg-[conic-gradient(from_0deg,transparent_90deg,rgba(139,26,26,0.05)_100deg)] rounded-full animate-[spin_8s_linear_infinite]"></div>

                    <!-- Central Analysis Window -->
                    <div class="absolute inset-20 border border-black/5 rounded-full flex items-center justify-center bg-white/80 backdrop-blur-2xl overflow-hidden shadow-[0_0_80px_rgba(0,0,0,0.03)]">
                        <!-- Waveform Visualization -->
                        <div class="absolute inset-0 flex items-center justify-around px-12 opacity-[0.07]">
                            <?php for($i=0; $i<12; $i++): ?>
                                <div class="w-1 bg-primary rounded-full animate-pulse" style="height: <?php echo rand(20, 80); ?>%; animation-delay: <?php echo $i * 0.2; ?>s"></div>
                            <?php endfor; ?>
                        </div>

                        <!-- Scanner Core Display -->
                        <div class="absolute inset-0 flex items-center justify-center">
                            <!-- Crosshair Overlay -->
                            <div class="absolute inset-0 z-30 pointer-events-none opacity-20">
                                <div class="absolute top-1/2 left-0 w-full h-[1px] bg-primary"></div>
                                <div class="absolute left-1/2 top-0 w-[1px] h-full bg-primary"></div>
                                <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-48 h-48 border border-primary rounded-full"></div>
                                <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-32 h-32 border border-primary/40 rounded-full"></div>
                            </div>

                            <div class="relative w-32 h-44 md:w-48 md:h-64 z-20 group">
                                <img src="<?php echo get_template_directory_uri(); ?>/assets/images/helivex-vial-red.png" 
                                     alt="Molecular Diagnostic Analysis" 
                                     class="w-full h-full object-contain drop-shadow-[0_10px_30px_rgba(0,0,0,0.3)]">
                                <div class="absolute inset-0 bg-primary/5 rounded-full blur-2xl -z-10 animate-pulse"></div>
                                
                                <!-- Scanning Line for Main Scanner -->
                                <div class="absolute left-0 w-full h-1 bg-primary/50 shadow-[0_0_15px_rgba(139,26,26,0.5)] animate-[scan_3s_easeInOut_infinite] z-30 pointer-events-none"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Exterior HUD Data Nodes -->
                    <?php
                    $nodes = [
                        ['label' => hvx('hud_node1_label', 'NODE_V.104'), 'val' => hvx('hud_node1_value', 'PURITY 99.242%'), 'pos' => 'top-0 left-0', 'color' => 'text-green-600', 'shadow' => 'shadow-green-100'],
                        ['label' => hvx('hud_node2_label', 'NODE_V.105'), 'val' => hvx('hud_node2_value', 'STERILITY - NO GROWTH'), 'pos' => 'top-0 right-0', 'color' => 'text-blue-600', 'shadow' => 'shadow-blue-100'],
                        ['label' => hvx('hud_node3_label', 'NODE_V.106'), 'val' => hvx('hud_node3_value', 'ENDOTOXINS < 0.0239 EU/mg'), 'pos' => 'bottom-0 left-0', 'color' => 'text-primary', 'shadow' => 'shadow-red-100'],
                        ['label' => hvx('hud_node4_label', 'NODE_V.107'), 'val' => hvx('hud_node4_value', 'QUANTITY 30.02mg'), 'pos' => 'bottom-0 right-0', 'color' => 'text-zinc-800', 'shadow' => 'shadow-zinc-100'],
                    ];
                    foreach ($nodes as $node): ?>
                        <div class="absolute p-3 md:p-4 bg-white/95 border border-black/5 rounded-xl backdrop-blur-md z-20 min-w-[120px] md:min-w-[140px] shadow-lg <?php echo $node['shadow'] . ' ' . $node['pos']; ?> hover:scale-105 transition-transform duration-300">
                            <div class="space-y-1 md:space-y-1.5">
                                <div class="flex items-center justify-between">
                                    <span class="text-[7px] md:text-[8px] font-mono text-black/30 tracking-widest"><?php echo $node['label']; ?></span>
                                    <div class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></div>
                                </div>
                                <div class="text-[10px] md:text-xs font-mono font-black <?php echo $node['color']; ?>"><?php echo $node['val']; ?></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Right Side: Data Interface -->
                <div class="w-full lg:w-1/2 space-y-12">
                    <div class="space-y-6">
                        <div class="flex items-center gap-4">
                            <div class="p-3 bg-primary/5 rounded-xl text-primary border border-primary/10">
                                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="15" x2="23" y2="15"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="15" x2="4" y2="15"/></svg>
                            </div>
                            <div class="space-y-0.5">
                                <h3 class="text-[10px] font-black tracking-[0.4em] text-primary uppercase"><?php ehvx('diag_label', 'Quantum Lab Interface v4.0'); ?></h3>
                                <div class="h-[1px] w-full bg-gradient-to-r from-primary/30 to-transparent"></div>
                            </div>
                        </div>
                        <h2 class="text-4xl sm:text-6xl font-black tracking-tighter text-zinc-900 leading-[0.85]">
                            <?php ehvx('diag_heading_1', 'ADVANCED'); ?> <br />
                            <span class="text-primary italic"><?php ehvx('diag_heading_2', 'MOLECULAR'); ?></span> <br />
                            <?php ehvx('diag_heading_3', 'DIAGNOSTICS'); ?>
                        </h2>
                        <p class="text-zinc-500 max-w-md text-base leading-relaxed">
                            <?php ehvx('diag_description', 'Real-time synthesis monitoring and purity verification. Our medical-grade infrastructure ensures every batch meets the Helivex Gold Standard.'); ?>
                        </p>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <!-- Metrics Card -->
                        <div class="bg-zinc-50 border border-black/[0.03] p-8 rounded-3xl space-y-6 shadow-sm hover:scale-[1.02] hover:-translate-y-2 transition-all duration-300">
                            <div class="flex items-center justify-between text-black/30">
                                <div class="flex items-center gap-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                                    <span class="text-[10px] font-black uppercase tracking-widest">Live Metrics</span>
                                </div>
                                <div class="flex gap-1.5">
                                    <div class="w-1 h-3 bg-primary/20 rounded-full"></div>
                                    <div class="w-1 h-3 bg-primary rounded-full"></div>
                                </div>
                            </div>
                            <div class="space-y-3">
                                <div class="flex justify-between items-center py-1 border-b border-black/5">
                                    <span class="text-[10px] uppercase tracking-wider text-black/40">Batch Purity</span>
                                    <span class="text-[10px] font-mono font-bold text-green-600">99.242%</span>
                                </div>
                                <div class="flex justify-between items-center py-1 border-b border-black/5">
                                    <span class="text-[10px] uppercase tracking-wider text-black/40">Stability Index</span>
                                    <span class="text-[10px] font-mono font-bold text-primary">Optimal</span>
                                </div>
                                <div class="flex justify-between items-center py-1 border-b border-black/5">
                                    <span class="text-[10px] uppercase tracking-wider text-black/40">Sequence ID</span>
                                    <span class="text-[10px] font-mono font-bold text-zinc-900">R30-00-1111</span>
                                </div>
                            </div>
                        </div>

                        <!-- Security/Verification Card -->
                        <div class="bg-zinc-50 border border-black/[0.03] p-8 rounded-3xl space-y-6 shadow-sm hover:scale-[1.02] hover:-translate-y-2 transition-all duration-300">
                            <div class="flex items-center justify-between text-black/30">
                                <div class="flex items-center gap-3">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                    <span class="text-[10px] font-black uppercase tracking-widest">Security Protocol</span>
                                </div>
                            </div>
                            <div class="flex items-center gap-6 py-2">
                                <div class="relative p-4 bg-white border border-black/5 rounded-2xl w-20 h-20 flex items-center justify-center shadow-inner overflow-hidden">
                                    <div class="relative w-12 h-12 opacity-80">
                                        <img src="<?php echo get_template_directory_uri(); ?>/assets/images/helivex-vial-red.png" 
                                             alt="Verified Peptide" 
                                             class="w-full h-full object-contain">
                                    </div>
                                    <!-- Verified Scanline - Moves from Top to Bottom -->
                                    <div class="absolute left-0 w-full h-[2px] bg-primary/60 shadow-[0_0_12px_rgba(139,26,26,0.6)] animate-[scan_1.5s_linear_infinite] z-20 pointer-events-none"></div>
                                </div>
                                <div class="space-y-1.5">
                                    <p class="text-[12px] font-black text-zinc-900 tracking-widest">VERIFIED</p>
                                    <p class="text-[9px] text-zinc-400 font-mono">ENCRYPTED_CHAIN_ID: 0x7F...3E</p>
                                </div>
                            </div>
                            <div class="space-y-2.5">
                                <div class="flex justify-between text-[8px] font-mono text-black/40 uppercase">
                                    <span>Validation Progress</span>
                                    <span>100%</span>
                                </div>
                                <div class="h-2 w-full bg-white border border-black/5 rounded-full overflow-hidden p-0.5">
                                    <div class="h-full bg-primary rounded-full w-full transition-all duration-1000"></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Bottom Status Bar -->
                    <div class="p-6 border border-primary/10 bg-primary/[0.02] rounded-2xl flex items-center justify-between backdrop-blur-md shadow-sm">
                        <div class="flex items-center gap-5">
                            <div class="relative">
                                <div class="w-3 h-3 rounded-full bg-primary animate-ping absolute inset-0 opacity-20"></div>
                                <div class="w-3 h-3 rounded-full bg-primary relative"></div>
                            </div>
                            <p class="text-[11px] font-mono text-primary font-black tracking-[0.2em] uppercase">
                                <?php ehvx('diag_status', 'Core Status: Nominal // Integrity Verified'); ?>
                            </p>
                        </div>
                        <div class="flex gap-5 items-center">
                            <div class="h-5 w-[1px] bg-primary/10"></div>
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-primary/30 cursor-pointer hover:text-primary transition-colors"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
</div>

<?php get_footer(); ?>
