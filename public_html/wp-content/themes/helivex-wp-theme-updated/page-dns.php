<?php
/**
 * Template Name: Do Not Sell My Personal Information
 */
get_header(); ?>

<main class="min-h-screen bg-white pt-32 pb-24 px-4">
    <div class="max-w-4xl mx-auto space-y-12">
        <header class="space-y-4">
            <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-100 text-zinc-500 text-[10px] font-black uppercase tracking-widest">
                <span class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                CCPA / CPRA Compliance
            </div>
            <h1 class="text-5xl font-black tracking-tighter uppercase italic leading-tight">Do Not Sell My<br>Personal Information</h1>
            <p class="text-zinc-500 font-medium uppercase tracking-widest text-xs leading-relaxed max-w-2xl">Under the California Consumer Privacy Act (CCPA) and CPRA, you have the right to opt-out of the "sale" or "sharing" of your personal information to third parties.</p>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-12 border-t border-zinc-100 pt-12">
            <div class="md:col-span-2 space-y-8">
                <section class="space-y-4">
                    <h2 class="text-xl font-black uppercase italic tracking-tight text-zinc-900">Your Right to Opt-Out</h2>
                    <div class="prose prose-zinc prose-sm text-zinc-600 leading-relaxed space-y-4">
                        <p>Helivex Labs values your privacy. We do not sell your personal information for monetary compensation. However, like many e-commerce companies, we may share certain information (such as cookies or device identifiers) with service providers to enhance your laboratory experience or provide relevant research updates.</p>
                        <p>Use the form below to formally submit a request to opt-out of any future "sale" or "sharing" of your data as defined by California law.</p>
                    </div>
                </section>

                <form action="#" class="bg-zinc-50 p-8 rounded-3xl space-y-6 border border-zinc-100">
                    <div class="space-y-2">
                        <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Institutional or Personal Email Address</label>
                        <input type="email" required class="w-full bg-white border-zinc-200 rounded-xl px-5 py-4 focus:ring-2 focus:ring-primary/20 transition-all text-sm" placeholder="researcher@institution.edu">
                    </div>
                    
                    <div class="space-y-2">
                        <label class="text-[10px] font-black uppercase tracking-widest text-zinc-400">Request Type</label>
                        <div class="grid grid-cols-1 gap-3">
                            <label class="flex items-center gap-3 p-4 bg-white rounded-xl border border-zinc-200 cursor-pointer hover:border-zinc-300 transition-all">
                                <input type="checkbox" checked class="rounded border-zinc-300 text-zinc-900 focus:ring-zinc-900">
                                <span class="text-xs font-bold text-zinc-700">Do Not Sell My Information</span>
                            </label>
                            <label class="flex items-center gap-3 p-4 bg-white rounded-xl border border-zinc-200 cursor-pointer hover:border-zinc-300 transition-all">
                                <input type="checkbox" class="rounded border-zinc-300 text-zinc-900 focus:ring-zinc-900">
                                <span class="text-xs font-bold text-zinc-700">Limit Use of Sensitive Personal Information</span>
                            </label>
                        </div>
                    </div>

                    <div class="space-y-4">
                        <button type="submit" class="w-full bg-zinc-900 text-white font-black uppercase tracking-widest py-5 rounded-xl hover:bg-primary transition-colors italic text-sm">Submit Privacy Request</button>
                        <p class="text-[9px] text-zinc-400 uppercase tracking-tighter text-center">We will process your request within 15 business days as required by law.</p>
                    </div>
                </form>
            </div>

            <div class="space-y-8">
                <div class="bg-zinc-900 p-6 rounded-3xl text-white space-y-4">
                    <h3 class="text-[10px] font-black uppercase tracking-widest text-zinc-500 italic">Privacy Operations</h3>
                    <p class="text-xs leading-relaxed text-zinc-300">You may also submit a request by contacting our Privacy Officer directly:</p>
                    <div class="space-y-2 pt-2">
                        <p class="text-xs font-bold">privacy@helivexlabs.com</p>
                        <p class="text-xs font-bold">+1 (800) 555-0199</p>
                    </div>
                </div>

                <div class="space-y-4 px-2">
                    <h4 class="text-[10px] font-black uppercase tracking-widest text-zinc-900">Verified Requests</h4>
                    <p class="text-[11px] text-zinc-500 leading-relaxed italic">To protect your laboratory data, we may require additional verification of your identity before processing this request.</p>
                </div>
            </div>
        </div>
    </div>
</main>

<?php get_footer(); ?>
