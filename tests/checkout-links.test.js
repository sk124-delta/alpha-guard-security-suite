const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const links = [...html.matchAll(/https:\/\/link\.payoneer\.com\/[^"'\s]+/g)].map((m) => m[0].replace(/&amp;/g, '&'));

test('checkout links exist', () => {
    assert.ok(links.length >= 2);
});

test('checkout links carry only token and src params and no email/account identifiers', () => {
    for (const link of links) {
        const url = new URL(link);
        assert.deepEqual([...url.searchParams.keys()].sort(), ['src', 't']);
        assert.doesNotMatch(link, /@|email|user|account/i);
    }
});

test('known limitation: tokens are static per plan (flagged for human decision, not changed)', () => {
    const tokens = new Set(links.map((l) => new URL(l).searchParams.get('t')));
    assert.equal(tokens.size, 2);
});
