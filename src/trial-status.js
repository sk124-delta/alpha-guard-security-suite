// Single source of truth for trial / subscription status.
// Inputs: the signed-in user's trial start (created_at) and subscription state
// (app_metadata.subscription_status === 'active', set by the billing side, never by the client).
(function (root) {
    const TRIAL_DAYS = 7;
    const DAY_MS = 86400000;

    function deriveTrialStatus(user, now) {
        const nowMs = typeof now === 'number' ? now : (now instanceof Date ? now.getTime() : Date.now());
        if (!user) {
            return { state: 'none', planLabel: 'No plan', headline: 'No active subscription', detail: 'Sign in or start a 7-day free trial.', daysLeft: 0, showBanner: false };
        }
        const subscription = user.app_metadata && user.app_metadata.subscription_status;
        if (subscription === 'active') {
            return { state: 'paid_active', planLabel: 'Paid plan', headline: 'Subscription active', detail: 'Your paid plan is active.', daysLeft: 0, showBanner: false };
        }
        const start = Date.parse(user.created_at || '');
        if (Number.isNaN(start)) {
            return { state: 'none', planLabel: 'No plan', headline: 'No active subscription', detail: 'Start a 7-day free trial or activate a 6-month plan.', daysLeft: 0, showBanner: false };
        }
        const daysLeft = Math.max(0, Math.ceil((start + TRIAL_DAYS * DAY_MS - nowMs) / DAY_MS));
        if (daysLeft <= 0) {
            return { state: 'trial_expired', planLabel: 'Trial ended', headline: 'Your 7-day free trial has ended', detail: 'Activate a 6-month plan to continue.', daysLeft: 0, showBanner: true };
        }
        const unit = daysLeft === 1 ? 'day' : 'days';
        return {
            state: 'trial_active',
            planLabel: '7-Day Free Trial',
            headline: `Free trial active: ${daysLeft} ${unit} left`,
            detail: `No card required - $0 charged. The trial ends automatically in ${daysLeft} ${unit}.`,
            daysLeft,
            showBanner: false
        };
    }

    const api = { deriveTrialStatus, TRIAL_DAYS };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.AG_TRIAL = api;
})(typeof window !== 'undefined' ? window : globalThis);
