const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cfg = require('../src/site-config.js');

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
