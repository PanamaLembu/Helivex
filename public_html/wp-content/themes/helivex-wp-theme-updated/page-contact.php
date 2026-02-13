<?php
/**
 * Template Name: Contact Us
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-6xl mx-auto space-y-16">
        <header class="space-y-4 max-w-2xl">
            <h1 class="text-5xl font-black tracking-tighter uppercase italic leading-none">Contact<br>Laboratory Support</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-xs leading-relaxed">Our technical team is available for laboratory inquiries, batch verification, and fulfillment support.</p>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-16">
            <div class="lg:col-span-2 space-y-12">
                <form action="#" class="space-y-8">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-2">
                            <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Full Name</label>
                            <input type="text" class="w-full bg-zinc-50 border-none rounded-2xl px-6 py-4 focus:ring-2 focus:ring-primary/20 transition-all" placeholder="Dr. Jane Smith">
                        </div>
                        <div class="space-y-2">
                            <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Institutional Email</label>
                            <input type="email" class="w-full bg-zinc-50 border-none rounded-2xl px-6 py-4 focus:ring-2 focus:ring-primary/20 transition-all" placeholder="jsmith@university.edu">
                        </div>
                    </div>
                    
                    <div class="space-y-2">
                        <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Inquiry Type</label>
                        <select class="w-full bg-zinc-50 border-none rounded-2xl px-6 py-4 focus:ring-2 focus:ring-primary/20 transition-all appearance-none">
                            <option>Batch Analysis / COA Request</option>
                            <option>Technical Compound Inquiry</option>
                            <option>Fulfillment & Shipping</option>
                            <option>Billing & Compliance</option>
                        </select>
                    </div>

                    <div class="space-y-2">
                        <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Message</label>
                        <textarea rows="6" class="w-full bg-zinc-50 border-none rounded-2xl px-6 py-4 focus:ring-2 focus:ring-primary/20 transition-all" placeholder="Please provide Batch ID for COA requests..."></textarea>
                    </div>

                    <button type="submit" class="bg-zinc-900 text-white font-black uppercase tracking-widest px-10 py-5 rounded-2xl hover:bg-primary transition-colors italic text-sm">Send Laboratory Inquiry</button>
                </form>
            </div>

            <div class="space-y-12">
                <div class="space-y-6">
                    <h3 class="text-sm font-black uppercase tracking-widest text-zinc-900 border-b border-zinc-100 pb-4">Direct Channels</h3>
                    <div class="space-y-4">
                        <div class="flex items-start gap-4">
                            <div class="w-10 h-10 bg-zinc-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                            </div>
                            <div>
                                <p class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Email</p>
                                <p class="font-bold text-zinc-900">support@helivexlabs.com</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-4">
                            <div class="w-10 h-10 bg-zinc-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
                            </div>
                            <div>
                                <p class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Technical Support</p>
                                <p class="font-bold text-zinc-900">+1 (800) 555-0199</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="space-y-6">
                    <h3 class="text-sm font-black uppercase tracking-widest text-zinc-900 border-b border-zinc-100 pb-4">Facility Location</h3>
                    <div class="space-y-4">
                        <div class="flex items-start gap-4">
                            <div class="w-10 h-10 bg-zinc-50 rounded-xl flex items-center justify-center flex-shrink-0">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
                            </div>
                            <div>
                                <p class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Headquarters</p>
                                <p class="font-bold text-zinc-900">123 Research Way, Suite 400<br>Austin, TX 78701, USA</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="p-6 bg-zinc-900 rounded-3xl text-white space-y-2">
                    <p class="text-[10px] font-black uppercase tracking-widest text-zinc-500">Business Hours</p>
                    <p class="text-sm font-bold italic">Mon — Fri: 9AM - 6PM CST</p>
                    <p class="text-[10px] text-zinc-400 leading-relaxed pt-2">Lab fulfillment is paused on federal holidays to maintain shipping integrity.</p>
                </div>
            </div>
        </div>
    </div>
</main>

<?php get_footer(); ?>
