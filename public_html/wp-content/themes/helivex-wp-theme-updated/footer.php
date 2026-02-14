<footer class="bg-muted border-t border-border pink-metallic-glow">
    <div class="container py-12 md:py-16">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div class="space-y-4">
                <h3 class="text-xl font-bold text-primary"><?php ehvx('footer_logo_text', 'HELIVEX LABS'); ?></h3>
                <p class="text-sm text-muted-foreground leading-relaxed">
                    <?php ehvx('footer_description', 'Premium quality research peptides and compounds. Tested for 99% purity and delivered with integrity to the scientific community.'); ?>
                </p>
                <div class="flex space-x-4">
                    <a href="#" class="text-muted-foreground hover:text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
                    </a>
                    <a href="#" class="text-muted-foreground hover:text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 4s-.7 2.1-2 3.4c1.6 10-9.4 17.3-18 11.6 2.2.1 4.4-.6 6-2C3 15.5.5 9.6 3 5c2.2 2.6 5.6 4.1 9 4-.9-4.2 4-6.6 7-3.8 1.1 0 3-1.2 3-1.2z"/></svg>
                    </a>
                    <a href="#" class="text-muted-foreground hover:text-primary">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>
                    </a>
                </div>
            </div>
            
            <div>
                <h4 class="font-bold mb-4">SHOP</h4>
                <ul class="space-y-2 text-sm text-muted-foreground">
                    <li><a href="<?php echo esc_url( wc_get_page_permalink( 'shop' ) ); ?>" class="hover:text-primary">All Products</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/coa' ) ); ?>" class="hover:text-primary">COA Archive</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/products?category=peptides' ) ); ?>" class="hover:text-primary">Peptides</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/products?category=research' ) ); ?>" class="hover:text-primary">Research Compounds</a></li>
                </ul>
            </div>
            
            <div>
                <h4 class="font-bold mb-4">SUPPORT</h4>
                <ul class="space-y-2 text-sm text-muted-foreground">
                    <li><a href="<?php echo esc_url( home_url( '/faq' ) ); ?>" class="hover:text-primary">FAQ</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/shipping' ) ); ?>" class="hover:text-primary">Shipping Policy</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/returns' ) ); ?>" class="hover:text-primary">Returns & Refunds</a></li>
                    <li><a href="<?php echo esc_url( home_url( '/terms' ) ); ?>" class="hover:text-primary">Terms of Service</a></li>
                </ul>
            </div>
            
            <div>
                <h4 class="font-bold mb-4">CONTACT</h4>
                <ul class="space-y-3 text-sm text-muted-foreground">
                    <li class="flex items-start gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mt-1"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        <span><?php ehvx('footer_email', 'support@helivexlabs.com'); ?></span>
                    </li>
                    <li class="flex items-start gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mt-1"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
                        <span><?php ehvx('footer_phone', '+1 (800) 555-0199'); ?></span>
                    </li>
                    <li class="flex items-start gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mt-1"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
                        <span><?php echo nl2br(hvx('footer_address', '123 Research Way, Suite 400, Austin, TX 78701, USA')); ?></span>
                    </li>
                </ul>
                <div class="mt-6 pt-6 border-t border-zinc-200">
                    <div class="flex flex-wrap items-center gap-4 opacity-60 grayscale hover:grayscale-0 transition-all duration-500">
                        <img src="https://upload.wikimedia.org/wikipedia/commons/5/5e/Visa_Inc._logo.svg" alt="Visa" class="h-5 w-auto block" style="height: 20px; width: auto;">
                        <img src="https://upload.wikimedia.org/wikipedia/commons/2/2a/Mastercard-logo.svg" alt="Mastercard" class="h-5 w-auto block" style="height: 20px; width: auto;">
                        <img src="https://upload.wikimedia.org/wikipedia/commons/b/b5/PayPal.svg" alt="PayPal" class="h-5 w-auto block" style="height: 20px; width: auto;">
                        <img src="https://upload.wikimedia.org/wikipedia/commons/b/b0/Apple_Pay_logo.svg" alt="Apple Pay" class="h-5 w-auto block" style="height: 20px; width: auto;">
                    </div>
                </div>
            </div>
        </div>
        
        <div class="mt-12 pt-8 border-t border-zinc-800 flex flex-col md:flex-row justify-between items-center gap-6">
            <p class="text-zinc-500 text-sm">&copy; <?php echo date('Y'); ?> <?php ehvx('footer_copyright', 'Helivex Labs. All Rights Reserved.'); ?></p>
            <div class="flex flex-wrap justify-center gap-6 text-xs font-bold uppercase tracking-widest text-zinc-400">
                <a href="/privacy-policy" class="hover:text-white transition-colors">Privacy Policy</a>
                <a href="/terms-of-service" class="hover:text-white transition-colors">Terms of Service</a>
                <a href="/compliance" class="hover:text-white transition-colors">RUO Compliance</a>
                <a href="/do-not-sell-my-info" class="hover:text-white transition-colors text-red-500/80 underline decoration-red-500/30 underline-offset-4">Do Not Sell My Personal Information</a>
            </div>
            <div class="flex items-center gap-4">
                <div class="px-3 py-1 border border-zinc-800 rounded text-[10px] text-zinc-500 font-bold uppercase tracking-tighter"><?php ehvx('footer_secure_badge', 'PCI DSS Compliant'); ?></div>
                <div class="px-3 py-1 border border-zinc-800 rounded text-[10px] text-zinc-500 font-bold uppercase tracking-tighter"><?php ehvx('footer_encrypt_badge', 'AES-256 Encrypted'); ?></div>
            </div>
        </div>
    </div>
</footer>
</div><!-- #page -->

<?php if (current_user_can('manage_options')) : ?>
    <!-- Admin Image Editor Modal -->
    <div id="admin-image-upload-modal">
        <div class="admin-modal-content">
            <div class="flex justify-between items-center border-b border-black/5 pb-4">
                <h3 class="text-lg font-black tracking-tight text-zinc-900 uppercase">Replace Image</h3>
                <button onclick="closeAdminModal()" class="text-zinc-400 hover:text-primary transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
            </div>
            
            <div class="space-y-4">
                <div class="p-4 bg-zinc-50 rounded-xl border border-black/[0.03]">
                    <p class="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-1">Target File</p>
                    <p id="admin-target-path-display" class="text-xs font-mono text-zinc-600 truncate"></p>
                </div>

                <div class="relative group">
                    <input type="file" id="admin-image-input" accept="image/*" class="hidden" onchange="handleAdminFileSelect(this)">
                    <label for="admin-image-input" class="flex flex-col items-center justify-center w-full h-48 border-2 border-dashed border-zinc-200 rounded-2xl cursor-pointer hover:border-primary/50 hover:bg-primary/[0.02] transition-all">
                        <div id="admin-preview-container" class="flex flex-col items-center justify-center py-6">
                            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-zinc-300 mb-3"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
                            <p class="text-xs font-bold text-zinc-500 uppercase tracking-widest">Select New Photo</p>
                        </div>
                        <img id="admin-image-preview" class="hidden w-full h-full object-contain p-4">
                    </label>
                </div>
            </div>

            <div class="flex gap-3">
                <button onclick="saveAdminImage()" id="admin-save-button" class="flex-1 bg-primary text-white font-black text-[10px] tracking-[0.2em] uppercase py-4 rounded-xl shadow-lg shadow-primary/20 hover:bg-accent transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed">
                    Save to Website
                </button>
            </div>
        </div>
    </div>

    <script>
    let currentTargetImg = null;
    let currentTargetPath = '';
    let currentProductId = null;

    function initAdminEditor() {
        const images = document.querySelectorAll('img');
        images.forEach(img => {
            // Check if already wrapped
            if (img.closest('.admin-editable-image-container')) return;

            const src = img.getAttribute('src');
            let isThemeAsset = false;
            let relativePath = '';
            let productId = null;

            // 1. Check if theme asset
            if (src && src.includes('/assets/images/')) {
                const pathParts = src.split('/assets/images/');
                // Strip query strings (like ?v=123) from the path
                relativePath = 'assets/images/' + pathParts[1].split('?')[0];
                isThemeAsset = true;
            }

            // 2. Check if WooCommerce product image
            // Look for product-ID in parent IDs or post-ID in parent classes
            const productContainer = img.closest('[id^="product-"], [class*="post-"].product');
            if (productContainer) {
                const idMatch = productContainer.id.match(/product-(\d+)/) || 
                              Array.from(productContainer.classList).find(c => c.startsWith('post-'))?.match(/post-(\d+)/);
                
                if (idMatch) {
                    productId = idMatch[1];
                }
            }

            if (isThemeAsset || productId) {
                // Wrap in editable container
                const wrapper = document.createElement('div');
                wrapper.className = 'admin-editable-image-container';
                if (img.className.includes('w-full')) wrapper.classList.add('w-full');
                
                img.parentNode.insertBefore(wrapper, img);
                wrapper.appendChild(img);
                
                // Add overlay
                const overlay = document.createElement('div');
                overlay.className = 'admin-edit-overlay';
                overlay.innerHTML = `
                    <div class="admin-edit-pencil" onclick="openAdminEditor(event, '${relativePath}', ${productId})">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                    </div>
                `;
                wrapper.appendChild(overlay);
            }
        });
    }

    function openAdminEditor(e, path, productId) {
        e.preventDefault();
        e.stopPropagation();
        currentTargetPath = path;
        currentProductId = productId;
        currentTargetImg = e.currentTarget.closest('.admin-editable-image-container').querySelector('img');
        
        const displayPath = productId ? `WooCommerce Product ID: ${productId}` : path;
        const modalTitle = productId ? 'Replace Product Photo' : 'Replace Theme Image';
        
        document.querySelector('#admin-image-upload-modal h3').textContent = modalTitle;
        document.getElementById('admin-target-path-display').textContent = displayPath;
        document.getElementById('admin-image-upload-modal').style.display = 'flex';
        
        // Reset preview
        document.getElementById('admin-image-preview').classList.add('hidden');
        document.getElementById('admin-preview-container').classList.remove('hidden');
        document.getElementById('admin-image-input').value = '';
    }

    function closeAdminModal() {
        document.getElementById('admin-image-upload-modal').style.display = 'none';
    }

    function handleAdminFileSelect(input) {
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const preview = document.getElementById('admin-image-preview');
                preview.src = e.target.result;
                preview.classList.remove('hidden');
                document.getElementById('admin-preview-container').classList.add('hidden');
            };
            reader.readAsDataURL(input.files[0]);
        }
    }

    async function saveAdminImage() {
        const input = document.getElementById('admin-image-input');
        if (!input.files || !input.files[0]) {
            alert('Please select an image first');
            return;
        }

        const button = document.getElementById('admin-save-button');
        button.disabled = true;
        button.textContent = 'Uploading...';

        const formData = new FormData();
        formData.append('action', 'helivex_replace_image');
        formData.append('image', input.files[0]);
        
        if (currentProductId) {
            formData.append('product_id', currentProductId);
        } else {
            formData.append('target_path', currentTargetPath);
        }

        try {
            const response = await fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();

            if (result.success) {
                // Update live preview on page
                if (result.data.new_url) {
                    currentTargetImg.src = result.data.new_url;
                } else {
                    const timestamp = new Date().getTime();
                    currentTargetImg.src = currentTargetImg.src.split('?')[0] + '?v=' + timestamp;
                }
                
                alert('Website updated successfully!');
                closeAdminModal();
            } else {
                alert('Error: ' + result.data);
            }
        } catch (error) {
            console.error('Upload failed:', error);
            alert('Upload failed. Check console.');
        } finally {
            button.disabled = false;
            button.textContent = 'Save to Website';
        }
    }

    document.addEventListener('DOMContentLoaded', initAdminEditor);
    // Re-init if content changes (e.g. infinite scroll)
    setInterval(initAdminEditor, 2000);
    </script>
<?php endif; ?>

<?php wp_footer(); ?>

</body>
</html>
