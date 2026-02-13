<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="profile" href="https://gmpg.org/xfn/11">
    
    <!-- Tailwind Play CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Google Fonts - Geist and Inter -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100..900&family=JetBrains+Mono:wght@100..800&display=swap" rel="stylesheet">
    <!-- Geist Font Alternative via CDN -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/geist@1.3.0/dist/fonts/geist-sans/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/geist@1.3.0/dist/fonts/geist-mono/style.css">

    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        background: '#ffffff',
                        foreground: '#1A1A1A',
                        primary: {
                            DEFAULT: '#8B1A1A', // Deep Logo Red
                            foreground: '#ffffff',
                        },
                        secondary: {
                            DEFAULT: '#F4A7A7', // Soft Logo Pink
                            foreground: '#4A0E0E', // Darkest Logo Maroon
                        },
                        accent: '#4A0E0E',
                        muted: {
                            DEFAULT: '#F9F3F3',
                            foreground: '#666666',
                        },
                        border: '#E5E5E5',
                    },
                    fontFamily: {
                        sans: ['Geist Sans', 'Inter', 'sans-serif'],
                        mono: ['Geist Mono', 'JetBrains Mono', 'monospace'],
                    },
                    animation: {
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                        'spin-slow': 'spin 40s linear infinite',
                        'spin-reverse': 'spin 25s linear infinite reverse',
                        'bounce-slow': 'bounce 3s infinite',
                    },
                    keyframes: {
                        scan: {
                            '0%, 100%': { top: '0%' },
                            '50%': { top: '100%' },
                        }
                    }
                }
            }
        }
    </script>

    <style type="text/tailwindcss">
        @layer base {
            :root {
                --background: #ffffff;
                --foreground: #1A1A1A;
                --primary: #8B1A1A;
                --primary-foreground: #ffffff;
                --secondary: #F4A7A7;
                --secondary-foreground: #4A0E0E;
                --accent: #4A0E0E;
                --muted: #F9F3F3;
                --muted-foreground: #666666;
                --border: #E5E5E5;
            }
            body {
                @apply bg-background text-foreground font-sans antialiased min-h-screen flex flex-col overflow-x-hidden;
                background: var(--background);
                color: var(--foreground);
            }
        }

        @layer components {
            .container {
                @apply max-w-7xl mx-auto px-4 sm:px-6 lg:px-8;
            }

            .btn-primary {
                @apply bg-primary text-primary-foreground px-6 py-3 rounded-md font-medium transition-all hover:bg-accent active:scale-95;
            }
            
            .btn-secondary {
                @apply bg-secondary text-secondary-foreground px-6 py-3 rounded-md font-medium transition-all hover:opacity-90 active:scale-95;
            }

            .reflective-glow {
                @apply relative overflow-hidden;
            }

            .reflective-glow::after {
                content: '';
                @apply absolute -inset-[100%] opacity-20 pointer-events-none;
                background: radial-gradient(circle at center, var(--secondary) 0%, transparent 70%);
                filter: blur(60px);
                z-index: -1;
            }

            .pink-metallic-glow {
                @apply relative border-2 border-secondary/40;
                box-shadow: 
                    0 0 15px rgba(244, 167, 167, 0.3),
                    inset 0 0 10px rgba(244, 167, 167, 0.2);
                background-image: linear-gradient(135deg, rgba(255,255,255,0.1) 0%, transparent 40%, rgba(255,255,255,0.05) 100%);
            }

            /* Pink Glow and Reflection for Red Text */
            .text-primary, 
            [class*="text-primary"],
            h1 span.text-primary,
            h2 span.text-primary,
            h3 span.text-primary,
            .btn-primary,
            .bg-primary,
            .hover\:text-primary:hover,
            .hover\:bg-primary:hover,
            .group:hover .group-hover\:text-primary,
            .group:hover .group-hover\:bg-primary {
                text-shadow: 
                    0 0 10px rgba(244, 167, 167, 0.4),
                    0 0 20px rgba(244, 167, 167, 0.2);
                position: relative;
            }

            /* Glow for red icons and images */
            svg.text-primary,
            .text-primary svg,
            [class*="text-primary"] svg,
            .bg-primary svg,
            .btn-primary svg,
            .hover\:text-primary:hover svg,
            .group:hover .group-hover\:text-primary svg {
                filter: drop-shadow(0 0 8px rgba(244, 167, 167, 0.4));
            }

            /* Subtle reflection effect for larger red text and headers */
            h1 span.text-primary, 
            h2 span.text-primary,
            h3 span.text-primary,
            .text-2xl.text-primary,
            .text-3xl.text-primary,
            .text-4xl.text-primary,
            .text-5xl.text-primary,
            .text-6xl.text-primary, 
            .text-7xl.text-primary, 
            .text-8xl.text-primary,
            h1:has(span.text-primary),
            h2:has(span.text-primary),
            h3:has(span.text-primary),
            a.text-primary,
            button.text-primary {
                -webkit-box-reflect: below -15% linear-gradient(transparent, rgba(244, 167, 167, 0.1));
            }

            /* Admin Image Editor Styles */
            .admin-editable-image-container {
                @apply relative group cursor-pointer z-[40];
            }
            .admin-edit-overlay {
                @apply absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center z-[100] rounded-lg pointer-events-none;
            }
            .admin-edit-pencil {
                @apply w-8 h-8 bg-white rounded-full flex items-center justify-center shadow-lg transform scale-90 group-hover:scale-100 transition-transform pointer-events-auto border border-primary/10 hover:bg-primary hover:text-white transition-all;
            }
            .admin-edit-pencil svg {
                @apply w-4 h-4 text-primary group-hover:text-white transition-colors;
            }
            #admin-image-upload-modal {
                @apply fixed inset-0 z-[9999] hidden items-center justify-center bg-black/60 backdrop-blur-sm p-4;
            }
            .admin-modal-content {
                @apply bg-white rounded-2xl p-8 max-w-md w-full shadow-2xl space-y-6 transform transition-all;
            }
        }
    </style>

    <?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<?php wp_body_open(); ?>

<header class="sticky top-0 z-50 w-full bg-white backdrop-blur-md pink-metallic-glow">
    <div class="container flex h-24 items-center justify-between">
        <div class="flex items-center gap-10">
            <a href="<?php echo esc_url( home_url( '/' ) ); ?>" class="flex items-center space-x-2 md:space-x-3 group">
                <div class="relative w-16 h-16 md:w-20 md:h-20 flex-shrink-0">
                    <img src="<?php echo get_template_directory_uri(); ?>/assets/images/logo.png" 
                         alt="Helivex Labs" 
                         class="w-full h-full object-contain drop-shadow-[0_0_8px_rgba(139,26,26,0.3)] group-hover:scale-110 transition-transform duration-300">
                </div>
                <div class="relative">
                    <span class="text-lg md:text-2xl font-bold tracking-tighter text-primary uppercase whitespace-nowrap flex items-center gap-1">
                        HELIVEX <span class="text-secondary-foreground font-light">LABS</span>
                        <div class="w-2 h-2 rounded-full bg-primary animate-pulse hidden md:block"></div>
                    </span>
                    <div class="absolute -bottom-1 left-0 w-0 h-[2px] bg-primary transition-all group-hover:w-full"></div>
                </div>
            </a>
            
            <nav class="hidden md:flex gap-8 text-[11px] font-bold tracking-widest uppercase">
                <a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="transition-colors hover:text-primary relative group">
                    SHOP
                    <span class="absolute -bottom-1 left-0 w-0 h-[1px] bg-primary transition-all group-hover:w-full"></span>
                </a>
                <a href="<?php echo esc_url( home_url( '/coa' ) ); ?>" class="transition-colors hover:text-primary relative group">
                    COA
                    <span class="absolute -bottom-1 left-0 w-0 h-[1px] bg-primary transition-all group-hover:w-full"></span>
                </a>
                <a href="<?php echo esc_url( home_url( '/about' ) ); ?>" class="transition-colors hover:text-primary relative group">
                    ABOUT
                    <span class="absolute -bottom-1 left-0 w-0 h-[1px] bg-primary transition-all group-hover:w-full"></span>
                </a>
                <a href="<?php echo esc_url( home_url( '/faq' ) ); ?>" class="transition-colors hover:text-primary relative group">
                    FAQ
                    <span class="absolute -bottom-1 left-0 w-0 h-[1px] bg-primary transition-all group-hover:w-full"></span>
                </a>
                <a href="<?php echo esc_url( home_url( '/contact' ) ); ?>" class="transition-colors hover:text-primary relative group">
                    CONTACT
                    <span class="absolute -bottom-1 left-0 w-0 h-[1px] bg-primary transition-all group-hover:w-full"></span>
                </a>
            </nav>
        </div>

        <div class="flex items-center gap-2">
            <div class="hidden lg:flex items-center mr-4 px-3 py-1 border border-primary/20 rounded-full bg-primary/5">
                <div class="w-1.5 h-1.5 rounded-full bg-primary animate-pulse mr-2"></div>
                <span class="text-[9px] font-mono text-primary font-bold tracking-tighter uppercase">SECURE_LINK: ACTIVE</span>
            </div>
            
            <a href="<?php echo esc_url( wc_get_page_permalink( 'myaccount' ) ); ?>" class="flex items-center gap-2 pl-2 pr-4 py-1.5 transition-colors hover:text-primary hover:bg-muted rounded-full group">
                <div class="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-primary group-hover:bg-primary group-hover:text-white transition-all">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </div>
            </a>

            <a href="<?php echo esc_url( wc_get_cart_url() ); ?>" class="p-2 transition-colors hover:text-primary hover:bg-muted rounded-full relative">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="21" r="1"/><circle cx="19" cy="21" r="1"/><path d="M2.05 2.05h2l2.66 12.42a2 2 0 0 0 2 1.58h9.78a2 2 0 0 0 1.95-1.57l1.65-7.43H5.12"/></svg>
                <?php if ( WC()->cart->get_cart_contents_count() > 0 ) : ?>
                    <span class="absolute top-1 right-1 h-3.5 w-3.5 rounded-full bg-primary text-[8px] font-bold text-white flex items-center justify-center">
                        <?php echo WC()->cart->get_cart_contents_count(); ?>
                    </span>
                <?php endif; ?>
            </a>
            
            <button id="mobile-menu-toggle" class="md:hidden p-2 transition-colors hover:text-primary">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
            </button>
        </div>
    </div>
    
    <!-- Mobile Menu -->
    <div id="mobile-menu" class="hidden md:hidden bg-white border-t border-secondary/20 pink-metallic-glow animate-in slide-in-from-top duration-300">
        <nav class="flex flex-col p-4 space-y-4 text-[11px] font-bold tracking-widest uppercase">
            <a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="p-2 transition-colors hover:text-primary">SHOP</a>
            <a href="<?php echo esc_url( home_url( '/coa' ) ); ?>" class="p-2 transition-colors hover:text-primary">COA</a>
            <a href="<?php echo esc_url( home_url( '/about' ) ); ?>" class="p-2 transition-colors hover:text-primary">ABOUT</a>
            <a href="<?php echo esc_url( home_url( '/faq' ) ); ?>" class="p-2 transition-colors hover:text-primary">FAQ</a>
            <a href="<?php echo esc_url( home_url( '/contact' ) ); ?>" class="p-2 transition-colors hover:text-primary">CONTACT</a>
        </nav>
    </div>
    
    <!-- Thick Red Bar from the photo -->
    <div class="h-8 w-full bg-primary"></div>

    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const toggle = document.getElementById('mobile-menu-toggle');
        const menu = document.getElementById('mobile-menu');
        
        if (toggle && menu) {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                menu.classList.toggle('hidden');
                console.log('Mobile menu toggled');
            });

            // Close menu when clicking outside
            document.addEventListener('click', function(e) {
                if (!menu.contains(e.target) && !toggle.contains(e.target)) {
                    menu.classList.add('hidden');
                }
            });

            // Close menu when clicking a link
            menu.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', () => {
                    menu.classList.add('hidden');
                });
            });
        }
    });
    </script>
</header>
