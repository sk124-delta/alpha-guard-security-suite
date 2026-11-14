// Single source for pricing display values, the Gumroad product catalog and the landing-page sample snapshot.
// Loads as a plain <script> in the browser (window.AG_CONFIG) and with require() in Node tests.
(function (root) {
    // 6-month Payoneer pricing that index.html currently displays. Changing a price here changes the
    // displayed amount only; checkout links stay in index.html until the Gumroad migration is decided.
    const PRICING = {
        growth: { label: 'Growth', price: 399, termMonths: 6, referenceMonthly: 79 },
        // No verified monthly Pro reference exists, so the Pro savings badge stays hidden.
        pro: { label: 'Pro', price: 1290, termMonths: 6, referenceMonthly: null }
    };

    // Illustrative numbers only. Not live metrics; the landing page labels them "Sample data".
    const SAMPLE_SNAPSHOT = { asOf: '2026-11-07', scans: 14820, threats: 28, notices: 25 };

    // Scans run once per day (scheduler.py). Do not describe them as continuous or 24/7.
    const SCAN_CADENCE_LABEL = 'daily';

    // Gumroad catalog. Each link is the base product URL (no tracking parameters).
    // confirmed: false blocks launch until the product, price and billing are verified in Gumroad.
    const GUMROAD_BASE = 'https://alphasecuritysuite.gumroad.com/l/';
    const gumroad = (slug) => (slug ? GUMROAD_BASE + slug : null);

    const TIERS = {
        growth: { code: 'G.T', name: 'Growth Tier' },
        pro: { code: 'P.T', name: 'Pro Tier' },
        enterprise: { code: 'E.T', name: 'Enterprise Tier' }
    };

    const SHIELDS = {
        course: { code: 'C.S', name: 'Course Shield' },
        media: { code: 'M.S', name: 'Media Shield' },
        executive: { code: 'E.S', name: 'Executive Shield' }
    };

    const PRODUCTS = [
        { id: 'ecom-small-b2c', name: 'Small B2C e-commerce stores', category: 'ecommerce',
          description: 'Shopify, Etsy, WooCommerce and Walmart sellers.',
          tier: 'growth', shield: null, priceUsd: 79, billing: 'monthly',
          gumroadUrl: gumroad('dbexqj'), confirmed: false },
        { id: 'ecom-mid-brands', name: 'Mid-size online brands', category: 'ecommerce',
          description: 'Established stores with large product catalogs.',
          tier: 'growth', shield: null, priceUsd: 79, billing: 'monthly',
          gumroadUrl: gumroad('lkqkkc'), confirmed: false },
        { id: 'fashion-boutique', name: 'Fashion & boutique apparel labels', category: 'ecommerce',
          description: 'Established apparel stores with large product catalogs.',
          tier: 'pro', shield: null, priceUsd: 249, billing: 'monthly',
          gumroadUrl: gumroad('cygzyw'), confirmed: false },
        { id: 'tech-accessories', name: 'Consumer tech & phone accessories', category: 'ecommerce',
          description: 'High-margin brands such as MagSafe cases and smartwatch accessories.',
          tier: null, shield: null, priceUsd: null, billing: 'monthly', // price unreadable in notes
          gumroadUrl: gumroad('hmpejz'), confirmed: false },
        { id: 'health-wellness', name: 'Health, wellness & cosmetic brands', category: 'ecommerce',
          description: 'Skincare and supplement lines whose lab badges and before/after photos are scraped.',
          tier: 'pro', shield: null, priceUsd: 249, billing: 'monthly',
          gumroadUrl: gumroad('oibele'), confirmed: false },
        { id: 'global-enterprise', name: 'Global enterprise retailers', category: 'ecommerce',
          description: 'High-volume brands with daily automated scanning.',
          tier: 'enterprise', shield: null, priceUsd: 899, billing: 'monthly',
          gumroadUrl: gumroad('hygggq'), confirmed: false },
        { id: 'influencer-merch', name: 'Influencer & creator merch stores', category: 'creators',
          description: 'YouTube, TikTok, streamers and podcasters whose designs are copied on marketplaces.',
          tier: null, shield: null, priceUsd: 119, billing: 'monthly', // notes say G.T / P.T; choose one
          gumroadUrl: gumroad('wbvjft'), confirmed: false },
        { id: 'edtech-course', name: 'Ed tech & course creators', category: 'creators',
          description: 'Course content protection.',
          tier: null, shield: 'course', priceUsd: 499, billing: 'monthly',
          gumroadUrl: null, confirmed: false }, // no link; irlzfz was reassigned to media producers
        { id: 'media-producers', name: 'YouTube creators & media producers', category: 'creators',
          description: 'Video and media protection.',
          tier: null, shield: 'media', priceUsd: 399, billing: 'monthly',
          gumroadUrl: gumroad('irlzfz'), confirmed: false }, // earlier listing said Ed Tech; confirm
        { id: 'digital-photographers', name: 'Digital photographers & stock studios', category: 'digital-assets',
          description: 'Photo and stock content protection.',
          tier: 'growth', shield: null, priceUsd: 99, billing: 'monthly',
          gumroadUrl: gumroad('gsvzuq'), confirmed: false },
        { id: 'saas-templates', name: 'Software (SaaS), apps & web template creators', category: 'digital-assets',
          description: 'UI templates, apps and web template protection.',
          tier: 'pro', shield: null, priceUsd: 199, billing: 'monthly',
          gumroadUrl: gumroad('fudbbv'), confirmed: false },
        { id: 'book-authors', name: 'Book authors & PDF publishers', category: 'digital-assets',
          description: 'eBook and PDF protection.',
          tier: 'growth', shield: null, priceUsd: 69, billing: 'monthly',
          gumroadUrl: gumroad('jroqz'), confirmed: false },
        { id: 'real-estate', name: 'Real estate agencies & architecture firms', category: 'specialized',
          description: 'Protection against fake rental listings and copied property photos.',
          tier: null, shield: null, priceUsd: 349, billing: 'monthly', // earlier listing showed $699; confirm
          gumroadUrl: gumroad('vlnxs'), confirmed: false },
        { id: 'web3-nft', name: 'Web3, NFT & digital art projects', category: 'specialized',
          description: 'Protection against look-alike domains and cloned community sites.',
          tier: null, shield: null, priceUsd: 699, billing: 'monthly', // earlier listing showed $599; confirm
          gumroadUrl: gumroad('izzea'), confirmed: false },
        { id: 'executive-impersonation', name: 'Executive & personal brand impersonation', category: 'specialized',
          description: 'Protection for C-suite leaders and public figures against cloned profiles.',
          tier: null, shield: 'executive', priceUsd: 599, billing: 'monthly',
          gumroadUrl: gumroad('jrwsha'), confirmed: false }
    ];

    function formatUsd(amount) {
        return '$' + amount.toLocaleString('en-US');
    }

    function referenceTotal(plan) {
        return plan.referenceMonthly == null ? null : plan.referenceMonthly * plan.termMonths;
    }

    function savings(plan) {
        const total = referenceTotal(plan);
        if (total == null) return null;
        const diff = total - plan.price;
        return diff > 0 ? diff : null;
    }

    function percent(part, whole) {
        return whole > 0 ? (part / whole * 100).toFixed(1) + '%' : 'n/a';
    }

    function planText(key, format) {
        const plan = PRICING[key];
        const amount = formatUsd(plan.price);
        if (format === 'amount') return amount;
        if (format === 'plan') return `${amount} / ${plan.termMonths} Months`;
        if (format === 'cta') return `Get ${plan.termMonths}-Month Plan (${amount})`;
        if (format === 'banner') return `${plan.label} ${plan.termMonths}-Month (${amount})`;
        return amount;
    }

    const api = {
        PRICING, SAMPLE_SNAPSHOT, SCAN_CADENCE_LABEL, TIERS, SHIELDS, PRODUCTS,
        formatUsd, referenceTotal, savings, percent, planText
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.AG_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);
