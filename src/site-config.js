
// Single source for the product catalog, sector list, pricing and the sample snapshot.
// Loads as a plain <script> in the browser (window.AG_CONFIG) and with require() in Node tests.
(function (root) {
    // Six-month plan values. Separate from the individual product catalog prices.
    const PRICING = {
        growth: { label: 'Growth', price: 399, termMonths: 6, referenceMonthly: 79 },
        // No verified monthly Pro reference exists, so the Pro savings badge stays hidden.
        pro: { label: 'Pro', price: 1290, termMonths: 6, referenceMonthly: null }
    };

    // Illustrative numbers only. Not live metrics; the page labels them "Sample data".
    const SAMPLE_SNAPSHOT = {
        asOf: '2026-11-07',
        scans: 14820,
        threats: 28,
        notices: 25
    };

    // Scans run once per day (api/index.py cron). Do not describe them as continuous or 24/7.
    const SCAN_CADENCE_LABEL = 'daily';

    const GUMROAD_BASE = 'https://alphasecuritysuite.gumroad.com/l/';

    // All 15 checkout links have been verified.
    const gumroad = (slug, verified) =>
        (verified && slug ? GUMROAD_BASE + slug : null);

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

    // The four sectors. Keys match PRODUCTS[].category.
    const SECTORS = [
        {
            key: 'ecommerce',
            label: 'E-Commerce & Retail Brands',
            blurb: 'Online sellers, apparel labels and retail catalogs.'
        },
        {
            key: 'creators',
            label: 'Creator Economy & Media',
            blurb: 'Creators, course makers and media producers.'
        },
        {
            key: 'digital-assets',
            label: 'Digital Assets & Creative Professionals',
            blurb: 'Photographers, software and template makers, and authors.'
        },
        {
            key: 'specialized',
            label: 'Specialized & VIP Protection',
            blurb: 'Real estate, Web3 projects and executive impersonation.'
        }
    ];

    // Each gumroadCode must also exist in billing.py PRODUCT_MAP.
    const PRODUCTS = [
        {
            id: 'ecom-small-b2c',
            name: 'Small B2C e-commerce stores',
            category: 'ecommerce',
            description: 'Shopify, Etsy, WooCommerce and Walmart sellers.',
            tier: 'growth',
            shield: null,
            priceUsd: 79,
            billing: 'monthly',
            gumroadCode: 'dbexqj',
            gumroadUrl: gumroad('dbexqj', true),
            confirmed: true
        },
        {
            id: 'ecom-mid-brands',
            name: 'Mid-size online brands',
            category: 'ecommerce',
            description: 'Established stores with large product catalogs.',
            tier: 'growth',
            shield: null,
            priceUsd: 79,
            billing: 'monthly',
            gumroadCode: 'lkqkkc',
            gumroadUrl: gumroad('lkqkkc', true),
            confirmed: true
        },
        {
            id: 'fashion-boutique',
            name: 'Fashion & boutique apparel labels',
            category: 'ecommerce',
            description: 'Established apparel stores with large product catalogs.',
            tier: 'pro',
            shield: null,
            priceUsd: 249,
            billing: 'monthly',
            gumroadCode: 'ltexsl',
            gumroadUrl: gumroad('ltexsl', true),
            confirmed: true
        },
        {
            id: 'tech-accessories',
            name: 'Consumer tech & phone accessories',
            category: 'ecommerce',
            description: 'High-margin brands such as MagSafe cases and smartwatch accessories.',
            tier: null,
            shield: null,
            priceUsd: 249,
            billing: 'monthly',
            gumroadCode: 'cygzyw',
            gumroadUrl: gumroad('cygzyw', true),
            confirmed: true
        },
        {
            id: 'health-wellness',
            name: 'Health, wellness & cosmetic brands',
            category: 'ecommerce',
            description: 'Skincare and supplement lines whose lab badges and before/after photos are scraped.',
            tier: 'pro',
            shield: null,
            priceUsd: 249,
            billing: 'monthly',
            gumroadCode: 'hmpejz',
            gumroadUrl: gumroad('hmpejz', true),
            confirmed: true
        },
        {
            id: 'global-enterprise',
            name: 'Global enterprise retailers',
            category: 'ecommerce',
            description: 'High-volume brands with daily automated scanning.',
            tier: 'enterprise',
            shield: null,
            priceUsd: 899,
            billing: 'monthly',
            gumroadCode: 'oibele',
            gumroadUrl: gumroad('oibele', true),
            confirmed: true
        },
        {
            id: 'influencer-merch',
            name: 'Influencer & creator merch stores',
            category: 'creators',
            description: 'YouTube, TikTok, streamers and podcasters whose designs are copied on marketplaces.',
            tier: null,
            shield: null,
            priceUsd: 119,
            billing: 'monthly',
            gumroadCode: 'hygggq',
            gumroadUrl: gumroad('hygggq', true),
            confirmed: true
        },
        {
            id: 'edtech-course',
            name: 'Ed tech & course creators',
            category: 'creators',
            description: 'Course content protection.',
            tier: null,
            shield: 'course',
            priceUsd: 499,
            billing: 'monthly',
            gumroadCode: 'wbvjft',
            gumroadUrl: gumroad('wbvjft', true),
            confirmed: true
        },
        {
            id: 'media-producers',
            name: 'YouTube creators & media producers',
            category: 'creators',
            description: 'Video and media protection.',
            tier: null,
            shield: 'media',
            priceUsd: 399,
            billing: 'monthly',
            gumroadCode: 'irlzfz',
            gumroadUrl: gumroad('irlzfz', true),
            confirmed: true
        },
        {
            id: 'digital-photographers',
            name: 'Digital photographers & stock studios',
            category: 'digital-assets',
            description: 'Photo and stock content protection.',
            tier: 'growth',
            shield: null,
            priceUsd: 99,
            billing: 'monthly',
            gumroadCode: 'gsvzuq',
            gumroadUrl: gumroad('gsvzuq', true),
            confirmed: true
        },
        {
            id: 'saas-templates',
            name: 'Software (SaaS), apps & web template creators',
            category: 'digital-assets',
            description: 'UI templates, apps and web template protection.',
            tier: 'pro',
            shield: null,
            priceUsd: 199,
            billing: 'monthly',
            gumroadCode: 'fudbbv',
            gumroadUrl: gumroad('fudbbv', true),
            confirmed: true
        },
        {
            id: 'book-authors',
            name: 'Book authors & PDF publishers',
            category: 'digital-assets',
            description: 'eBook and PDF protection.',
            tier: 'growth',
            shield: null,
            priceUsd: 69,
            billing: 'monthly',
            gumroadCode: 'jroqz',
            gumroadUrl: gumroad('jroqz', true),
            confirmed: true
        },
        {
            id: 'real-estate',
            name: 'Real estate agencies & architecture firms',
            category: 'specialized',
            description: 'Protection against fake rental listings and copied property photos.',
            tier: null,
            shield: null,
            priceUsd: 349,
            billing: 'monthly',
            gumroadCode: 'vlnxs',
            gumroadUrl: gumroad('vlnxs', true),
            confirmed: true
        },
        {
            id: 'web3-nft',
            name: 'Web3, NFT & digital art projects',
            category: 'specialized',
            description: 'Protection against look-alike domains and cloned community sites.',
            tier: null,
            shield: null,
            priceUsd: 599,
            billing: 'monthly',
            gumroadCode: 'izzea',
            gumroadUrl: gumroad('izzea', true),
            confirmed: true
        },
        {
            id: 'executive-impersonation',
            name: 'Executive & personal brand impersonation',
            category: 'specialized',
            description: 'Protection for C-suite leaders and public figures against cloned profiles.',
            tier: null,
            shield: 'executive',
            priceUsd: 599,
            billing: 'monthly',
            gumroadCode: 'jrwsha',
            gumroadUrl: gumroad('jrwsha', true),
            confirmed: true
        }
    ];

    function productsInSector(key) {
        return PRODUCTS.filter((p) => p.category === key);
    }

    function formatUsd(amount) {
        return '$' + amount.toLocaleString('en-US');
    }

    function referenceTotal(plan) {
        return plan.referenceMonthly == null
            ? null
            : plan.referenceMonthly * plan.termMonths;
    }

    function savings(plan) {
        const total = referenceTotal(plan);
        if (total == null) return null;

        const diff = total - plan.price;
        return diff > 0 ? diff : null;
    }

    function percent(part, whole) {
        return whole > 0
            ? (part / whole * 100).toFixed(1) + '%'
            : 'n/a';
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
        PRICING,
        SAMPLE_SNAPSHOT,
        SCAN_CADENCE_LABEL,
        TIERS,
        SHIELDS,
        SECTORS,
        PRODUCTS,
        productsInSector,
        formatUsd,
        referenceTotal,
        savings,
        percent,
        planText
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }

    root.AG_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);
