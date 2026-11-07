// Single source for pricing display values and the landing-page sample snapshot.
// Changing a price here changes the displayed amount only; Payoneer checkout links live in index.html.
(function (root) {
    const PRICING = {
        growth: { label: 'Growth', price: 399, termMonths: 6, referenceMonthly: 79 },
        // referenceMonthly is null because no monthly Pro reference price exists in the code base;
        // the savings badge is hidden until a verified reference is supplied.
        pro: { label: 'Pro', price: 1290, termMonths: 6, referenceMonthly: null }
    };

    // Illustrative numbers only. They are NOT live metrics; the landing page labels them "Sample data".
    const SAMPLE_SNAPSHOT = {
        asOf: '2026-11-07',
        scans: 14820,
        threats: 28,
        notices: 25
    };

    const SCAN_CADENCE_LABEL = 'daily';

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

    const api = { PRICING, SAMPLE_SNAPSHOT, SCAN_CADENCE_LABEL, formatUsd, referenceTotal, savings, percent, planText };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.AG_CONFIG = api;
})(typeof window !== 'undefined' ? window : globalThis);
