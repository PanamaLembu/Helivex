<?php
/**
 * Template Name: Privacy Policy & Compliance
 */
get_header(); ?>

<!-- 
    FORCE OVERWRITE: This template hardcodes the compliance content to ensure 
    that default WordPress "suggested text" blocks never appear.
-->
<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-16">
        <header class="space-y-6">
            <div class="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-zinc-900 text-white text-[10px] font-black uppercase tracking-[0.2em]">
                <span class="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                PCI DSS v4.0 & NACHA Compliant Protocol
            </div>
            <h1 class="text-6xl font-black tracking-tighter uppercase italic leading-none">Privacy & Data<br>Protection Policy</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-xs leading-relaxed max-w-2xl border-l-2 border-zinc-100 pl-6">
                This document serves as the official Privacy Policy for Helivex Labs. It outlines our strict data handling protocols required for high-risk processing, including ACH (NACHA), PCI DSS, and CCPA compliance.
                <br><span class="text-zinc-900 font-black">STRICTLY FOR RESEARCH USE ONLY.</span>
            </p>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-12 border-t border-zinc-100 pt-16">
            <!-- Sidebar Navigation -->
            <aside class="lg:col-span-1 hidden lg:block space-y-4 sticky top-32 h-fit">
                <nav class="flex flex-col gap-2">
                    <a href="#payment-security" class="text-[10px] font-black uppercase tracking-widest text-zinc-900 py-2 border-b border-zinc-900">01. Payment Security</a>
                    <a href="#data-collection" class="text-[10px] font-black uppercase tracking-widest text-zinc-400 hover:text-zinc-900 transition-colors py-2 border-b border-zinc-100">02. Data Collection</a>
                    <a href="#consumer-rights" class="text-[10px] font-black uppercase tracking-widest text-zinc-400 hover:text-zinc-900 transition-colors py-2 border-b border-zinc-100">03. Consumer Rights</a>
                    <a href="#compliance" class="text-[10px] font-black uppercase tracking-widest text-zinc-400 hover:text-zinc-900 transition-colors py-2 border-b border-zinc-100">04. RUO Standards</a>
                </nav>
            </aside>

            <!-- Main Content -->
            <div class="lg:col-span-3 space-y-20">
                
                <!-- Section 1: Payment Security -->
                <section id="payment-security" class="space-y-8">
                    <div class="space-y-4">
                        <h2 class="text-3xl font-black uppercase italic tracking-tight">01. Financial Data Integrity</h2>
                        <p class="text-zinc-600 text-sm leading-relaxed">As a high-risk research chemical provider, our payment security protocols exceed standard e-commerce requirements.</p>
                    </div>

                    <div class="grid grid-cols-1 gap-6">
                        <div class="p-8 bg-zinc-900 rounded-[2rem] text-white space-y-4 shadow-xl">
                            <div class="flex items-center gap-4 text-zinc-500">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                <span class="text-[10px] font-black uppercase tracking-widest">PCI DSS v4.0 Standard</span>
                            </div>
                            <h3 class="text-xl font-bold italic">AES-256 Encryption at Rest</h3>
                            <p class="text-zinc-400 text-xs leading-relaxed">All cardholder data is processed through a Level 1 PCI-Certified gateway. We utilize AES-256 encryption for all sensitive information at rest and TLS 1.3 for all data in transit.</p>
                        </div>

                        <div class="p-8 bg-zinc-50 rounded-[2rem] border border-zinc-100 space-y-4">
                            <div class="flex items-center gap-4 text-zinc-400">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 0 0 3-3V8a3 3 0 0 0-3-3H6a3 3 0 0 0-3 3v8a3 3 0 0 0 3 3z"/></svg>
                                <span class="text-[10px] font-black uppercase tracking-widest">NACHA / Plaid Compliance</span>
                            </div>
                            <h3 class="text-xl font-bold italic text-zinc-900">ACH Tokenization</h3>
                            <p class="text-zinc-500 text-xs leading-relaxed">For ACH payments, we utilize Plaid for instant account verification. We never store bank account or routing numbers; all financial data is converted into secure, one-time-use tokens.</p>
                        </div>
                    </div>
                </section>

                <!-- Section 2: Data Collection -->
                <section id="data-collection" class="space-y-8">
                    <div class="space-y-4">
                        <h2 class="text-3xl font-black uppercase italic tracking-tight">02. Information Collection</h2>
                        <p class="text-zinc-600 text-sm leading-relaxed">We collect only the data necessary to verify the institutional nature of our researchers and fulfill laboratory orders.</p>
                    </div>

                    <div class="space-y-4">
                        <div class="flex items-start gap-6 p-6 border-b border-zinc-50">
                            <span class="text-[10px] font-black text-zinc-300 pt-1">TYPE A</span>
                            <div class="space-y-1">
                                <h4 class="text-xs font-black uppercase tracking-widest text-zinc-900">Personal Identifiers</h4>
                                <p class="text-xs text-zinc-500">Legal name, shipping/billing address, and institutional email for order tracking.</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-6 p-6 border-b border-zinc-50">
                            <span class="text-[10px] font-black text-zinc-300 pt-1">TYPE B</span>
                            <div class="space-y-1">
                                <h4 class="text-xs font-black uppercase tracking-widest text-zinc-900">Laboratory Metadata</h4>
                                <p class="text-xs text-zinc-500">Batch IDs, COA requests, and compound specification inquiries.</p>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Section 3: Consumer Rights -->
                <section id="consumer-rights" class="space-y-8">
                    <div class="space-y-4">
                        <h2 class="text-3xl font-black uppercase italic tracking-tight">03. CCPA / CPRA Privacy Rights</h2>
                        <p class="text-zinc-600 text-sm leading-relaxed">California residents have specific rights regarding the "sale" and "sharing" of their information.</p>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="p-8 bg-zinc-50 rounded-3xl space-y-3">
                            <h4 class="text-[10px] font-black uppercase tracking-widest text-zinc-900">Right to Opt-Out</h4>
                            <p class="text-[11px] text-zinc-500 leading-relaxed">You may opt-out of data sharing by visiting our <a href="/do-not-sell-my-info" class="text-zinc-900 underline font-bold">Privacy Portal</a>.</p>
                        </div>
                        <div class="p-8 bg-zinc-50 rounded-3xl space-y-3">
                            <h4 class="text-[10px] font-black uppercase tracking-widest text-zinc-900">Right to Deletion</h4>
                            <p class="text-[11px] text-zinc-500 leading-relaxed">Request full deletion of your record, excluding tax and laboratory compliance logs.</p>
                        </div>
                    </div>
                </section>

                <!-- Section 4: Compliance -->
                <section id="compliance" class="space-y-8">
                    <div class="space-y-4">
                        <h2 class="text-3xl font-black uppercase italic tracking-tight">04. RUO Scientific Disclosure</h2>
                        <p class="text-zinc-600 text-sm leading-relaxed">Our data protocols are designed to protect the integrity of the research supply chain.</p>
                    </div>

                    <div class="p-10 bg-red-50 rounded-[2.5rem] border border-red-100 space-y-6">
                        <div class="w-12 h-12 bg-red-500/10 rounded-2xl flex items-center justify-center">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                        </div>
                        <div class="space-y-2">
                            <h4 class="text-xs font-black uppercase tracking-widest text-red-600">Strict RUO Protocol</h4>
                            <p class="text-sm text-red-900 leading-relaxed font-medium">Helivex Labs does not share data with medical providers, insurance companies, or consumer health databases. All information is used strictly for internal laboratory fulfillment of Research Use Only (RUO) compounds.</p>
                        </div>
                    </div>
                </section>

                <!-- Contact Block -->
                <div class="p-12 bg-zinc-900 rounded-[3rem] text-center space-y-8 text-white">
                    <div class="space-y-2">
                        <h3 class="text-2xl font-black uppercase italic tracking-tight">Privacy Officer</h3>
                        <p class="text-xs text-zinc-500 uppercase tracking-widest">Institutional Compliance & Data Integrity</p>
                    </div>
                    <div class="flex flex-col md:flex-row justify-center gap-12">
                        <div class="space-y-1">
                            <p class="text-[9px] font-black uppercase tracking-widest text-zinc-600">Email</p>
                            <p class="text-sm font-bold italic">privacy@helivexlabs.com</p>
                        </div>
                        <div class="space-y-1">
                            <p class="text-[9px] font-black uppercase tracking-widest text-zinc-600">Direct Line</p>
                            <p class="text-sm font-bold italic">+1 (800) 555-0199</p>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    </div>
</main>

<?php get_footer(); ?>
