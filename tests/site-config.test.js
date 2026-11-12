const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cfg = require('../src/site-config.js');

// ---- Existing pricing and landing-page tests (unchanged) ----

test('growth savings computed from config', () => {
    assert.equal(cfg.savings(cfg.PRICING.growth), 75);
    assert.equal(cfg.referenceTotal(cfg.PRICING.growth), 474);
});

test('pro badge hidden without a reference price', () => {
    assert.equal(cfg.savings(cfg.PRICING.pro), null);
});

test('prices unchanged', () => {
    assert.equal(cfg.PRICING.growth.price, 399);
    assert.equal(cfg.PRICING.pro.price, 1290);
});

test('percentage is computed from the variables', () => {
    const { notices, threats } = cfg.SAMPLE_SNAPSHOT;
    assert.equal(cfg.percent(notices, threats), '89.3%');
    assert.equal(cfg.percent(1, 0), 'n/a');
});

test('formatted plan strings', () => {
    assert.equal(cfg.planText('growth', 'plan'), '$399 / 6 Months');
    assert.equal(cfg.planText('pro', 'cta'), 'Get 6-Month Plan ($1,290)');
});

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

test('landing page labels sample data and has no hardcoded live claim', () => {
    assert.match(html, /Sample data/);
    assert.doesNotMatch(html, /current operational snapshot/i);
    assert.doesNotMatch(html, /SAVE \$204/);
});

// ---- Gumroad product catalog tests (new) ----

const { PRODUCTS, TIERS, SHIELDS } = cfg;
const GUMROAD_PREFIX = 'https://alphasecuritysuite.gumroad.com/l/';

test('product ids are unique', () => {
    const ids = PRODUCTS.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length);
});

test('product names are unique', () => {
    const names = PRODUCTS.map((p) => p.name);
    assert.equal(new Set(names).size, names.length);
});

test('product prices are positive numbers or null', () => {
    for (const p of PRODUCTS) {
        assert.ok(p.priceUsd === null || (Number.isFinite(p.priceUsd) && p.priceUsd > 0), p.id);
    }
});

test('Gumroad links are base product URLs on the seller domain', () => {
    for (const p of PRODUCTS) {
        if (p.gumroadUrl === null) continue;
        assert.ok(p.gumroadUrl.startsWith(GUMROAD_PREFIX), p.id);
        assert.ok(!p.gumroadUrl.includes('?'), `${p.id} contains tracking parameters`);
        assert.ok(!p.gumroadUrl.includes('#'), `${p.id} contains a fragment`);
    }
});

test('no two products share a Gumroad link', () => {
    const links = PRODUCTS.map((p) => p.gumroadUrl).filter(Boolean);
    assert.equal(new Set(links).size, links.length);
});

test('product tiers and shields refer to defined codes', () => {
    for (const p of PRODUCTS) {
        if (p.tier !== null) assert.ok(p.tier in TIERS, p.id);
        if (p.shield !== null) assert.ok(p.shield in SHIELDS, p.id);
    }
});

test('product copy does not claim 24/7 scanning', () => {
    for (const p of PRODUCTS) {
        assert.ok(!/24\/7/.test(p.description), p.id);
    }
});

// Runs only when LAUNCH=1, after every product is confirmed.
test('launch gate: every product is confirmed, priced, linked and tiered',
    { skip: process.env.LAUNCH !== '1' },
    () => {
        const blockers = [];
        for (const p of PRODUCTS) {
            if (!p.confirmed) blockers.push(`${p.id}: not confirmed`);
            if (p.priceUsd === null) blockers.push(`${p.id}: price missing`);
            if (p.gumroadUrl === null) blockers.push(`${p.id}: Gumroad link missing`);
            if (p.tier === null && p.shield === null) blockers.push(`${p.id}: tier missing`);
        }
        assert.deepEqual(blockers, []);
    }
);