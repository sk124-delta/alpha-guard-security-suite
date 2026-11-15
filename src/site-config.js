// Single source for the product catalog, sector list, pricing and the sample snapshot.
// Loads as a plain <script> in the browser (window.AG_CONFIG) and with require() in Node tests.
(function (root) {
    // Payoneer 6-month values. Not shown on the page. Kept for the pricing decision and the tests.
    const PRICING = {
        growth: { label: 'Growth', price: 399, termMonths: 6, referenceMonthly: 79 },
        // No verified monthly Pro reference exists, so the Pro savings badge stays hidden.
        pro: { label: 'Pro', price: 1290, termMonths: 6, referenceMonthly: null }
    };

    // Illustrative numbers only. Not live metrics; the page labels them "Sample data".
    const SAMPLE_SNAPSHOT = { asOf: '2026-11-07', scans: 14820, threats: 28, notices: 25 };

    // Scans run once per day (api/index.py cron). Do not describe them as continuous or 24/7.
    const SCAN_CADENCE_LABEL = 'daily';

    const GUMROAD_BASE = 'https://alphasecuritysuite.gumroad.com/l/';
    // A link is shown only when its Gumroad page has been checked and matches this product.
    // Set verified: true only after you have opened the link and confirmed the title and price.
    const gumroad = (slug, verified) => (verified && slug ? GUMROAD_BASE + slug : null);

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

    // The four sectors, shown with equal weight in the explorer. Keys match PRODUCTS[].category.
    const SECTORS = [
        { key: 'ecommerce', label: 'E-Commerce & Retail Brands',
          blurb: 'Online sellers, apparel labels and retail catalogs.' },
        { key: 'creators', label: 'Creator Economy & Media',
          blurb: 'Creators, course makers and media producers.' },
        { key: 'digital-assets', label: 'Digital Assets & Creative Professionals',
          blurb: 'Photographers, software and template makers, and authors.' },
        { key: 'specialized', label: 'Specialized & VIP Protection',
          blurb: 'Real estate, Web3 projects and executive impersonation.' }
    ];

    // Each entry: the site's description and price, and the Gumroad code that sells it.
    // gumroadUrl is null for any product whose Gumroad page is not yet confirmed.
    const PRODUCTS = [
        { id: 'ecom-small-b2c', name: 'Small B2C e-commerce stores', category: 'ecommerce',
          description: 'Shopify, Etsy, WooCommerce and Walmart sellers.',
          tier: 'growth', shield: null, priceUsd: 79, billing: 'monthly',
          gumroadCode: 'dbexqj', gumroadUrl: gumroad('dbexqj', false), confirmed: false },
        { id: 'ecom-mid-brands', name: 'Mid-size online brands', category: 'ecommerce',
          description: 'Established stores with large product catalogs.',
          tier: 'growth', shield: null, priceUsd: 79, billing: 'monthly',
          gumroadCode: 'lkqkkc', gumroadUrl: gumroad('lkqkkc', true), confirmed: false },
        { id: 'fashion-boutique', name: 'Fashion & boutique apparel labels', category: 'ecommerce',
          description: 'Established apparel stores with large product catalogs.',
          tier: 'pro', shield: null, priceUsd: 249, billing: 'monthly',
          gumroadCode: 'cygzyw', gumroadUrl: gumroad('cygzyw', false), confirmed: false },
        { id: 'tech-accessories', name: 'Consumer tech & phone accessories', category: 'ecommerce',
          description: 'High-margin brands such as MagSafe cases and smartwatch accessories.',
          tier: null, shield: null, priceUsd: null, billing: 'monthly',
          gumroadCode: 'hmpejz', gumroadUrl: gumroad('hmpejz', false), confirmed: false },
        { id: 'health-wellness', name: 'Health, wellness & cosmetic brands', category: 'ecommerce',
          description: 'Skincare and supplement lines whose lab badges and before/after photos are scraped.',
          tier: 'pro', shield: null, priceUsd: 249, billing: 'monthly',
          gumroadCode: 'oibele', gumroadUrl: gumroad('oibele', false), confirmed: false },
        { id: 'global-enterprise', name: 'Global enterprise retailers', category: 'ecommerce',
          description: 'High-volume brands with daily automated scanning.',
          tier: 'enterprise', shield: null, priceUsd: 899, billing: 'monthly',
          gumroadCode: 'hygggq', gumroadUrl: gumroad('hygggq', false), confirmed: false },
        { id: 'influencer-merch', name: 'Influencer & creator merch stores', category: 'creators',
          description: 'YouTube, TikTok, streamers and podcasters whose designs are copied on marketplaces.',
          tier: null, shield: null, priceUsd: 119, billing: 'monthly',
          gumroadCode: 'wbvjft', gumroadUrl: gumroad('wbvjft', false), confirmed: false },
        { id: 'edtech-course', name: 'Ed tech & course creators', category: 'creators',
          description: 'Course content protection.',
          tier: null, shield: 'course', priceUsd: 499, billing: 'monthly',
          gumroadCode: null, gumroadUrl: null, confirmed: false },
        { id: 'media-producers', name: 'YouTube creators & media producers', category: 'creators',
          description: 'Video and media protection.',
          tier: null, shield: 'media', priceUsd: 399, billing: 'monthly',
          gumroadCode: 'irlzfz', gumroadUrl: gumroad('irlzfz', true), confirmed: false },
        { id: 'digital-photographers', name: 'Digital photographers & stock studios', category: 'digital-assets',
          description: 'Photo and stock content protection.',
          tier: 'growth', shield: null, priceUsd: 99, billing: 'monthly',
          gumroadCode: 'gsvzuq', gumroadUrl: gumroad('gsvzuq', false), confirmed: false },
        { id: 'saas-templates', name: 'Software (SaaS), apps & web template creators', category: 'digital-assets',
          description: 'UI templates, apps and web template protection.',
          tier: 'pro', shield: null, priceUsd: 199, billing: 'monthly',
          gumroadCode: 'fudbbv', gumroadUrl: gumroad('fudbbv', false), confirmed: false },
        { id: 'book-authors', name: 'Book authors & PDF publishers', category: 'digital-assets',
          description: 'eBook and PDF protection.',
          tier: 'growth', shield: null, priceUsd: 69, billing: 'monthly',
          gumroadCode: 'jroqz', gumroadUrl: gumroad('jroqz', false), confirmed: false },
        { id: 'real-estate', name: 'Real estate agencies & architecture firms', category: 'specialized',
          description: 'Protection against fake rental listings and copied property photos.',
          tier: null, shield: null, priceUsd: 349, billing: 'monthly',
          gumroadCode: 'izzea', gumroadUrl: gumroad('izzea', false), confirmed: false },
        { id: 'web3-nft', name: 'Web3, NFT & digital art projects', category: 'specialized',
          description: 'Protection against look-alike domains and cloned community sites.',
          tier: null, shield: null, priceUsd: 599, billing: 'monthly',
          gumroadCode: 'jrwsha', gumroadUrl: gumroad('jrwsha', false), confirmed: false },
        { id: 'executive-impersonation', name: 'Executive & personal brand impersonation', category: 'specialized',
          description: 'Protection for C-suite leaders and public figures against cloned profiles.',
          tier: null, shield: 'executive', priceUsd: 599, billing: 'monthly',
          gumroadCode: 'vlnxs', gumroadUrl: gumroad('vlnxs', false), confirmed: false }
    ];

    function productsInSector(key) {
        return PRODUCTS.filter((p) => p.category === key);
    }

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
        PRICING, SAMPLE_SNAPSHOT, SCAN_CADENCE_LABEL, TIERS, SHIELDS, SECTORS, PRODUCTS,
        productsInSector, formatUsd, referenceTotal, savings, percent, planText
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.AG_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);