const test = require('node:test');
const assert = require('node:assert/strict');
const { deriveTrialStatus } = require('../src/trial-status.js');

const DAY = 86400000;
const now = Date.parse('2026-03-10T12:00:00Z');
const startedAgo = (days) => new Date(now - days * DAY).toISOString();

test('trial active', () => {
    const s = deriveTrialStatus({ created_at: startedAgo(2) }, now);
    assert.equal(s.state, 'trial_active');
    assert.equal(s.daysLeft, 5);
    assert.equal(s.showBanner, false);
});

test('trial expired', () => {
    const s = deriveTrialStatus({ created_at: startedAgo(7) }, now);
    assert.equal(s.state, 'trial_expired');
    assert.equal(s.showBanner, true);
    assert.doesNotMatch(s.headline, /active/i);
});

test('paid active overrides an old trial start', () => {
    const s = deriveTrialStatus({ created_at: startedAgo(90), app_metadata: { subscription_status: 'active' } }, now);
    assert.equal(s.state, 'paid_active');
    assert.equal(s.showBanner, false);
});

test('no subscription', () => {
    assert.equal(deriveTrialStatus(null, now).state, 'none');
    assert.equal(deriveTrialStatus({}, now).state, 'none');
});
