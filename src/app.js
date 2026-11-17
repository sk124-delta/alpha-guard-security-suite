import * as auth from './supabase.js';

const cfg = window.AG_CONFIG;
const $ = (id) => document.getElementById(id);
const VIEWS = ['explorer', 'wizard', 'dashboard'];

let currentUser = null;
let isAdmin = false;
let step = 1;
let scanResult = null;

// ---------- helpers

function el(tag, attrs = {}, text) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([key, value]) => {
    if (value != null) node.setAttribute(key, value);
  });
  if (text != null) node.textContent = text;
  return node;
}

function setStatus(node, message = '', isError = false) {
  if (!node) return;
  node.textContent = message;
  node.classList.toggle('error', Boolean(isError && message));
}

function normalizeDomain(raw) {
  let value = (raw || '').trim().toLowerCase();
  if (!value) return '';
  if (!value.includes('://')) value = 'https://' + value;
  try {
    return new URL(value).hostname.replace(/^www\./, '');
  } catch (e) {
    return '';
  }
}

function isValidDomain(domain) {
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain);
}

function isValidEmail(value) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
}

function errorText(data, fallback) {
  return typeof data?.detail === 'string' ? data.detail : fallback;
}

async function accessToken() {
  const session = await auth.getCurrentSession();
  return session?.access_token || null;
}

// ---------- views

function showView(name) {
  if (name === 'dashboard' && !currentUser) {
    openAuth('login');
    return;
  }
  VIEWS.forEach((view) => {
    const panel = $(`view-${view}`);
    if (panel) panel.hidden = view !== name;
  });
  document.querySelectorAll('.nav-btn').forEach((btn) => {
    if (btn.dataset.view === name) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
  window.scrollTo({ top: 0 });
}

// ---------- explorer

function renderSectors() {
  const grid = $('sector-grid');
  grid.replaceChildren();
  cfg.SECTORS.forEach((sector) => {
    const count = cfg.productsInSector(sector.key).length;
    const btn = el('button', {
      type: 'button',
      class: 'sector-btn',
      'aria-pressed': 'false',
      'data-sector': sector.key,
    });
    btn.append(
      el('span', { class: 'count' }, `${count} protected categories`),
      el('span', { class: 'sector-title' }, sector.label),
      el('span', { class: 'sector-blurb' }, sector.blurb)
    );
    grid.appendChild(btn);
  });
}

function productCard(product) {
  const card = el('article', { class: 'product' });
  let tier = 'Plan pending';
  if (product.tier && cfg.TIERS[product.tier]) tier = cfg.TIERS[product.tier].name;
  else if (product.shield && cfg.SHIELDS[product.shield]) tier = cfg.SHIELDS[product.shield].name;
  const price = product.priceUsd == null
    ? 'Price pending'
    : `${cfg.formatUsd(product.priceUsd)} per month`;

  card.append(el('h4', {}, product.name), el('p', {}, product.description));
  card.append(el('p', { class: 'meta' }, `${tier} · ${price}`));
  if (product.gumroadUrl) {
    card.append(el('a', {
      class: 'btn btn-secondary',
      href: product.gumroadUrl,
      target: '_blank',
      rel: 'noopener noreferrer',
    }, 'Open checkout'));
  } else {
    card.append(el('p', { class: 'muted' }, 'Checkout link pending'));
  }
  return card;
}

function selectSector(key) {
  document.querySelectorAll('.sector-btn').forEach((btn) => {
    btn.setAttribute('aria-pressed', String(btn.dataset.sector === key));
  });
  const sector = cfg.SECTORS.find((s) => s.key === key);
  const panel = $('sector-panel');
  panel.replaceChildren();
  if (!sector) return;
  const grid = el('div', { class: 'product-grid' });
  cfg.productsInSector(key).forEach((p) => grid.appendChild(productCard(p)));
  panel.append(el('h3', {}, sector.label), grid);
}

// ---------- wizard

function fillNiches() {
  const key = $('ob-sector').value;
  const niche = $('ob-niche');
  niche.replaceChildren(
    el('option', { value: '' }, key ? 'Choose a niche' : 'Choose a sector first')
  );
  cfg.productsInSector(key).forEach((p) => {
    niche.appendChild(el('option', { value: p.id }, p.name));
  });
}

function populateWizard() {
  const sectorSelect = $('ob-sector');
  sectorSelect.replaceChildren(el('option', { value: '' }, 'Choose a sector'));
  cfg.SECTORS.forEach((s) => {
    sectorSelect.appendChild(el('option', { value: s.key }, s.label));
  });
  fillNiches();
}

function goToStep(n) {
  step = n;
  for (let i = 1; i <= 3; i++) $(`step-${i}`).hidden = i !== n;
  document.querySelectorAll('.steps li').forEach((li) => {
    if (Number(li.dataset.step) === n) li.setAttribute('aria-current', 'step');
    else li.removeAttribute('aria-current');
  });
}

function selectedNicheName() {
  const product = cfg.PRODUCTS.find((p) => p.id === $('ob-niche').value);
  return product ? product.name : 'Not selected';
}

function nextFromStep1() {
  if (!$('ob-sector').value || !$('ob-niche').value) {
    setStatus($('step1-status'), 'Choose a sector and a niche to continue.', true);
    return;
  }
  setStatus($('step1-status'), '');
  goToStep(2);
}

function renderResult() {
  const box = $('scan-result');
  box.replaceChildren();
  const r = scanResult;

  if (!r.valid) {
    box.append(
      el('p', {}, `No store was detected at ${r.domain}.`),
      el('p', { class: 'muted' }, r.message || 'This page does not appear to be a store or product catalog.')
    );
    return;
  }

  const rows = [
    ['Store', r.domain],
    ['Detected category', r.detected_category || 'Not detected'],
    ['Product images found', String(r.catalog_images_indexed ?? 'Unknown')],
    ['Suggested plan', r.recommended_tier || 'Not available'],
    ['Niche you selected', selectedNicheName()],
  ];
  const list = el('dl', { class: 'ledger' });
  rows.forEach(([label, value]) => {
    const row = el('div');
    row.append(el('dt', {}, label), el('dd', {}, value));
    list.appendChild(row);
  });
  box.append(list);

  if (r.inspection_note) box.append(el('p', { class: 'muted' }, r.inspection_note));
  box.append(el('p', { class: 'muted' },
    'Plan prices are listed in the explorer. Your trial starts once you have an account.'));
}

async function runScan() {
  const status = $('scan-status');
  const input = $('ob-url');
  const domain = normalizeDomain(input.value);
  const errorBox = $('ob-url-error');

  if (!domain || !isValidDomain(domain)) {
    input.setAttribute('aria-invalid', 'true');
    errorBox.textContent = 'Enter a valid store URL, e.g. https://yourstore.com';
    errorBox.hidden = false;
    input.focus();
    return;
  }
  input.removeAttribute('aria-invalid');
  errorBox.hidden = true;

  const button = $('run-scan');
  button.disabled = true;
  setStatus(status, 'Checking your public store pages…');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25000);
  try {
    const response = await fetch('/api/v1/inspect-domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: domain }),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(errorText(data, 'The inspection service is unavailable right now.'));
    }
    scanResult = { domain, ...data };
    renderResult();
    setStatus(status, 'Inspection complete.');
    goToStep(3);
  } catch (err) {
    const message = err.name === 'AbortError'
      ? 'The check took too long. Please try again.'
      : (err.message || 'Inspection failed.');
    setStatus(status, message, true);
  } finally {
    clearTimeout(timer);
    button.disabled = false;
  }
}

// ---------- sign-in dialog

function openAuth(view = 'login') {
  const dialog = $('auth-dialog');
  if (typeof dialog.showModal === 'function') {
    if (!dialog.open) dialog.showModal();
  } else {
    dialog.setAttribute('open', '');
  }
  switchAuth(view);
}

function switchAuth(view) {
  ['login', 'signup', 'forgot'].forEach((name) => {
    $(`form-${name}`).hidden = name !== view;
  });
  $('auth-tabs').hidden = view === 'forgot';
  $('tab-login').setAttribute('aria-selected', String(view === 'login'));
  $('tab-signup').setAttribute('aria-selected', String(view === 'signup'));
  $('auth-title').textContent = view === 'signup' ? 'Create account'
    : view === 'forgot' ? 'Reset password' : 'Sign in';
  setStatus($('auth-status'), '');
  const first = $(`form-${view}`).querySelector('input');
  if (first) first.focus();
}

function setFieldError(id, message) {
  const input = $(id);
  const error = $(`${id}-error`);
  input.setAttribute('aria-invalid', message ? 'true' : 'false');
  error.textContent = message;
  error.hidden = !message;
}

function validateSignup() {
  const values = {
    name: $('s-name').value.trim(),
    email: $('s-email').value.trim().toLowerCase(),
    domain: normalizeDomain($('s-url').value),
    password: $('s-password').value,
    confirm: $('s-confirm').value,
  };
  const errors = {
    's-name': values.name ? '' : 'Enter your name.',
    's-email': isValidEmail(values.email) ? '' : 'Enter a valid email address.',
    's-url': isValidDomain(values.domain) ? '' : 'Enter a valid store URL, e.g. https://acmestore.com',
    's-password': values.password.length >= 8 ? '' : 'Password must be at least 8 characters.',
    's-confirm': values.confirm === values.password ? '' : 'Passwords do not match.',
  };
  Object.entries(errors).forEach(([id, message]) => setFieldError(id, message));
  const firstBad = Object.keys(errors).find((id) => errors[id]);
  if (firstBad) {
    $(firstBad).focus();
    return null;
  }
  return values;
}

async function handleLogin(event) {
  event.preventDefault();
  const email = $('l-email').value.trim().toLowerCase();
  const password = $('l-password').value;
  if (!isValidEmail(email) || !password) {
    setStatus($('auth-status'), 'Enter your email and password.', true);
    return;
  }
  setStatus($('auth-status'), 'Signing in…');
  try {
    const data = await auth.handleSignIn(email, password);
    const user = data?.session?.user || data?.user;
    if (!user) throw new Error('Sign in failed. Please try again.');
    applySession(user);
    $('auth-dialog').close();
    showView('dashboard');
  } catch (err) {
    setStatus($('auth-status'), err.message || 'Sign in failed.', true);
  }
}

async function handleSignup(event) {
  event.preventDefault();
  const values = validateSignup();
  if (!values) return;
  setStatus($('auth-status'), 'Creating your account…');
  try {
    const availability = await fetch('/api/v1/auth/check-availability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: values.email, store_url: values.domain }),
    }).catch(() => null);
    if (availability && availability.status === 400) {
      const info = await availability.json().catch(() => ({}));
      throw new Error(errorText(info, 'This email or store is already registered.'));
    }

    const data = await auth.handleSignUp(values.email, values.password, values.name, values.domain);
    const session = data?.session || null;

    // Welcome notice. The password is never sent.
    const headers = { 'Content-Type': 'application/json' };
    if (session?.access_token) headers.Authorization = `Bearer ${session.access_token}`;
    fetch('/api/v1/auth/register', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: values.name, email: values.email, store_url: values.domain }),
    }).catch((err) => console.error('Welcome notice failed:', err));

    if (!session) {
      switchAuth('login');
      setStatus($('auth-status'), 'Account created. Check your email to confirm your address, then sign in.');
      return;
    }
    applySession(session.user || data.user);
    $('auth-dialog').close();
    showView('dashboard');
  } catch (err) {
    setStatus($('auth-status'), err.message || 'Could not create your account.', true);
  }
}

async function handleForgot(event) {
  event.preventDefault();
  const email = $('f-email').value.trim().toLowerCase();
  if (!isValidEmail(email)) {
    setStatus($('auth-status'), 'Enter a valid email address.', true);
    return;
  }
  setStatus($('auth-status'), 'Sending…');
  try {
    await auth.handlePasswordReset(email);
    // Same message whether or not the account exists, so the form can't reveal who has an account.
    setStatus($('auth-status'), 'If an account exists for that email, a reset link has been sent.');
  } catch (err) {
    console.error('Password reset failed:', err);
    setStatus($('auth-status'), 'Password reset is unavailable right now. Please try again later.', true);
  }
}

async function handleSignOut() {
  try {
    await auth.handleSignOut();
  } catch (err) {
    console.error('Sign out failed:', err);
  }
  applySession(null);
  showView('explorer');
}

function startTrial() {
  if (!currentUser) openAuth('signup');
  else showView('dashboard');
}

// ---------- session, trial and dashboard

function renderTrial() {
  let headline = currentUser ? 'Trial status unavailable' : 'No active subscription';
  let plan = 'No plan';
  let detail = 'Sign in to see your plan.';
  const trial = window.AG_TRIAL;
  if (currentUser && trial && typeof trial.deriveTrialStatus === 'function') {
    const status = trial.deriveTrialStatus(isAdmin ? null : currentUser);
    headline = status.headline;
    plan = status.planLabel;
    detail = status.detail;
  }
  $('dash-trial').textContent = headline;
  $('dash-plan').textContent = plan;
  $('plan-detail').textContent = detail;
  $('case-status').textContent = headline.toUpperCase();
}

function applySession(user) {
  currentUser = user && user.email ? user : null;
  isAdmin = Boolean(currentUser) && ['admin', 'legal'].includes(currentUser.app_metadata?.role);

  const label = currentUser
    ? (currentUser.user_metadata?.store_name || currentUser.user_metadata?.full_name || currentUser.email)
    : '';
  $('user-label').textContent = label;
  $('user-label').hidden = !currentUser;
  $('sign-in-btn').hidden = Boolean(currentUser);
  $('sign-out-btn').hidden = !currentUser;
  $('dash-store').textContent = currentUser
    ? (currentUser.user_metadata?.store_url || label)
    : 'Your store';
  $('admin-panel').hidden = !isAdmin;

  renderTrial();
  if (!currentUser && !$('view-dashboard').hidden) showView('explorer');
}

async function restoreSession() {
  try {
    const session = await auth.getCurrentSession();
    applySession(session?.user || null);
    auth.onAuthStateChange((next) => applySession(next?.user || null));
  } catch (err) {
    console.error('Could not restore session:', err);
    applySession(null);
  }
}

// ---------- admin

async function loadNotices() {
  const status = $('notice-status');
  const body = $('notice-rows');
  body.replaceChildren();
  if (!isAdmin) {
    setStatus(status, 'Admin access required.', true);
    return;
  }
  setStatus(status, 'Loading…');
  try {
    const token = await accessToken();
    if (!token) throw new Error('Sign in again to load notices.');
    const response = await fetch('/api/v1/admin/notices', {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(`Could not load notices (HTTP ${response.status}).`);
    const notices = await response.json();
    if (!Array.isArray(notices)) throw new Error('Unexpected response from the server.');
    if (!notices.length) {
      setStatus(status, 'No notices yet.');
      return;
    }
    notices.forEach((n) => {
      const row = el('tr');
      row.append(
        el('td', {}, `#${n.notice_id ?? ''} · ${n.target_infringing_url ?? ''}`),
        el('td', {}, n.recipient ?? ''),
        el('td', {}, n.similarity_score != null ? `${n.similarity_score}%` : ''),
        el('td', {}, n.status ?? '')
      );
      body.appendChild(row);
    });
    setStatus(status, `${notices.length} notice(s) loaded.`);
  } catch (err) {
    setStatus(status, err.message || 'Could not load notices.', true);
  }
}

async function prepareDraft(event) {
  event.preventDefault();
  const status = $('draft-status');
  const output = $('draft-output');
  output.hidden = true;
  output.textContent = '';

  if (!$('d-confirm').checked) {
    setStatus(status, 'Tick the confirmation box to continue.', true);
    $('d-confirm').focus();
    return;
  }

  const payload = {
    store_id: Number($('d-store-id').value),
    host_abuse_email: $('d-abuse').value.trim(),
    target_infringing_url: $('d-target').value.trim(),
    infringing_image_url: $('d-infr-img').value.trim(),
    original_image_url: $('d-orig-img').value.trim(),
  };
  if (!payload.store_id || !isValidEmail(payload.host_abuse_email)
      || !payload.target_infringing_url || !payload.infringing_image_url || !payload.original_image_url) {
    setStatus(status, 'Fill in every field with valid values.', true);
    return;
  }

  setStatus(status, 'Preparing draft…');
  try {
    const token = await accessToken();
    if (!token) throw new Error('Sign in again to continue.');
    const response = await fetch('/api/v1/scan/execute-takedown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(errorText(data, `Request failed (HTTP ${response.status}).`));
    }
    setStatus(status, `${data.message || 'Draft prepared.'} Review all evidence before sending.`);
    if (data.notice_draft) {
      output.textContent = data.notice_draft.html || JSON.stringify(data.notice_draft, null, 2);
      output.hidden = false;
    }
  } catch (err) {
    setStatus(status, err.message || 'Could not prepare the draft.', true);
  }
}

// ---------- theme and sample data

function setTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  try {
    localStorage.setItem('theme', mode);
  } catch (e) {
    // Storage blocked: the theme still applies for this visit.
  }
  const btn = $('theme-toggle');
  btn.textContent = mode === 'dark' ? 'Light mode' : 'Dark mode';
  btn.setAttribute('aria-pressed', String(mode === 'dark'));
}

function fillSample() {
  const s = cfg.SAMPLE_SNAPSHOT;
  $('sample-scans').textContent = s.scans.toLocaleString('en-US');
  $('sample-threats').textContent = s.threats.toLocaleString('en-US');
  $('sample-notices').textContent = s.notices.toLocaleString('en-US');
  $('sample-as-of').textContent = s.asOf;
  $('sample-summary').textContent =
    `Sample data: ${s.notices} of ${s.threats} example threats have a notice dispatched (${cfg.percent(s.notices, s.threats)}).`;
}

// ---------- wiring

function bindEvents() {
  document.querySelectorAll('.nav-btn').forEach((btn) => {
    btn.addEventListener('click', () => showView(btn.dataset.view));
  });

  document.querySelectorAll('[data-action]').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.dataset.action === 'start-trial') startTrial();
      if (btn.dataset.action === 'close-auth') $('auth-dialog').close();
    });
  });

  $('sign-in-btn').addEventListener('click', () => openAuth('login'));
  $('sign-out-btn').addEventListener('click', handleSignOut);
  $('theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    setTheme(next);
  });

  $('sector-grid').addEventListener('click', (event) => {
    const btn = event.target.closest('[data-sector]');
    if (btn) selectSector(btn.dataset.sector);
  });

  $('ob-sector').addEventListener('change', fillNiches);
  document.querySelectorAll('[data-step-next]').forEach((btn) => {
    btn.addEventListener('click', nextFromStep1);
  });
  document.querySelectorAll('[data-step-prev]').forEach((btn) => {
    btn.addEventListener('click', () => goToStep(Number(btn.dataset.stepPrev)));
  });
  $('run-scan').addEventListener('click', runScan);
  // Pressing Enter in the URL field runs the check, not a page reload.
  $('wizard-form').addEventListener('submit', (event) => {
    event.preventDefault();
    if (step === 2) runScan();
  });

  $('auth-dialog').addEventListener('click', (event) => {
    const btn = event.target.closest('[data-auth-view]');
    if (btn) switchAuth(btn.dataset.authView);
  });
  $('form-login').addEventListener('submit', handleLogin);
  $('form-signup').addEventListener('submit', handleSignup);
  $('form-forgot').addEventListener('submit', handleForgot);

  $('load-notices').addEventListener('click', loadNotices);
  $('draft-form').addEventListener('submit', prepareDraft);
}

function init() {
  const saved = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  setTheme(saved);
  bindEvents();

  if (!cfg || !Array.isArray(cfg.SECTORS) || !Array.isArray(cfg.PRODUCTS)) {
    $('sector-panel').textContent = 'Plan data failed to load. Please refresh the page.';
    return;
  }

  renderSectors();
  populateWizard();
  fillSample();
  applySession(null);
  restoreSession();
}

init();