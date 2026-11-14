const test = require('node:test');
const assert = require('node:assert/strict');
const trial = require('../src/trial-status.js');

const DAY = 86400000;
const START = Date.parse('2026-11-01T00:00:00Z');
const userStartingAt = (ms, extra = {}) => ({ created_at: new Date(ms).toISOString(), app_metadata: {}, ...extra });

test('no user: no plan', () => {
    assert.equal(trial.deriveTrialStatus(null).state, 'none');
});

test('first moments of a trial: 7 days left, active', () => {
    const s = trial.deriveTrialStatus(userStartingAt(START), START + 1000);
    assert.equal(s.state, 'trial_active');
    assert.equal(s.daysLeft, 7);
    assert.equal(s.showBanner, false);
});

test('days left never exceeds the trial length', () => {
    const s = trial.deriveTrialStatus(userStartingAt(START), START - DAY);
    assert.equal(s.daysLeft, 7);
});

test('after 7 days the trial has ended and the banner shows', () => {
    const s = trial.deriveTrialStatus(userStartingAt(START), START + 8 * DAY);
    assert.equal(s.state, 'trial_expired');
    assert.equal(s.showBanner, true);
});

test('an active subscription overrides an expired trial', () => {
    const user = userStartingAt(START, { app_metadata: { subscription_status: 'active' } });
    const s = trial.deriveTrialStatus(user, START + 30 * DAY);
    assert.equal(s.state, 'paid_active');
    assert.equal(s.showBanner, false);
});

test('missing start date gives no plan, not a false trial', () => {
    const s = trial.deriveTrialStatus({ app_metadata: {} }, START);
    assert.equal(s.state, 'none');
});