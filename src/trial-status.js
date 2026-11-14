// Single source of truth for trial and subscription status.
// Reads only from the user object: created_at (trial start) and app_metadata.subscription_status.
// Only the server or billing side can set app_metadata; the browser never writes these values.
(function (root) {
    const TRIAL_DAYS = 7;
    const DAY_MS = 86400000;

    const NO_PLAN = {
        state: 'none',
        planLabel: 'No plan',
        headline: 'No active subscription',
        detail: 'Sign in to see your plan.',
        daysLeft: 0,
        showBanner: false
    };

    function nowMillis(now) {
        if (typeof now === 'number') return now;
        if (now instanceof Date) return now.getTime();
        return Date.now();
    }

    function deriveTrialStatus(user, now) {
        if (!user) return { ...NO_PLAN };

        const subscription = user.app_metadata && user.app_metadata.subscription_status;
        if (subscription === 'active') {
            return {
                state: 'paid_active',
                planLabel: 'Paid plan',
                headline: 'Subscription active',
                detail: 'Your paid plan is active.',
                daysLeft: 0,
                showBanner: false
            };
        }

        const start = Date.parse(user.created_at || '');
        if (Number.isNaN(start)) {
            return { ...NO_PLAN, detail: 'Your account start date is unavailable. Contact support.' };
        }

        const remainingMs = (start + TRIAL_DAYS * DAY_MS) - nowMillis(now);
        if (remainingMs <= 0) {
            return {
                state: 'trial_expired',
                planLabel: 'Trial ended',
                headline: 'Your 7-day free trial has ended',
                detail: 'Choose a plan to continue.',
                daysLeft: 0,
                showBanner: true
            };
        }

        // Capped at the trial length, so a clock that runs ahead never shows more days than the trial has.
        const daysLeft = Math.min(TRIAL_DAYS, Math.ceil(remainingMs / DAY_MS));
        const unit = daysLeft === 1 ? 'day' : 'days';
        return {
            state: 'trial_active',
            planLabel: '7-Day Free Trial',
            headline: `Free trial active: ${daysLeft} ${unit} left`,
            detail: `Your trial ends automatically in ${daysLeft} ${unit}.`,
            daysLeft,
            showBanner: false
        };
    }

    const api = { deriveTrialStatus, TRIAL_DAYS };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.AG_TRIAL = api;
})(typeof window !== 'undefined' ? window : globalThis);