import { supabase, getCurrentSession, handleSignOut } from './supabase.js';

const $ = (id) => document.getElementById(id);
const ADMIN_ROLES = ['admin', 'legal'];
const TICKET_STATUSES = ['open', 'in_progress', 'resolved'];
let adminEmail = '';

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

function formatTime(value) {
  if (!value) return '';
  return new Date(value).toLocaleString();
}

function isAdmin(user) {
  return ADMIN_ROLES.includes(user?.app_metadata?.role);
}

// Records every admin action. The database policy only lets admins insert here.
async function audit(action, targetId) {
  const { error } = await supabase.from('admin_audit_log').insert({
    actor: adminEmail,
    action,
    target_id: String(targetId ?? ''),
  });
  if (error) console.error('Audit write failed:', error.message);
  return !error;
}

// ---------- access gate

function showDenied(title, text) {
  $('gate-title').textContent = title;
  $('gate-text').textContent = text;
  $('gate-link').hidden = false;
  $('admin-app').hidden = true;
}

async function checkAccess() {
  if (!supabase) {
    showDenied('Admin is unavailable', 'Sign-in is not configured on this page.');
    return false;
  }
  const session = await getCurrentSession().catch(() => null);
  const user = session?.user;
  if (!user) {
    showDenied('Sign in required', 'Sign in on the public site with your admin account, then open this page again.');
    return false;
  }
  if (!isAdmin(user)) {
    showDenied('Access denied', 'This account does not have admin access.');
    return false;
  }
  adminEmail = user.email;
  $('admin-user').textContent = user.email;
  $('gate').hidden = true;
  $('admin-app').hidden = false;
  return true;
}

// ---------- tabs

function showTab(name) {
  ['support', 'notices', 'auth', 'audit'].forEach((tab) => {
    $(`tab-${tab}`).hidden = tab !== name;
  });
  document.querySelectorAll('[data-tab]').forEach((btn) => {
    btn.setAttribute('aria-selected', String(btn.dataset.tab === name));
  });
}

// ---------- support tickets

async function loadTickets() {
  const status = $('support-status');
  const body = $('support-rows');
  body.replaceChildren();
  setStatus(status, 'Loading…');

  let query = supabase
    .from('support_tickets')
    .select('id, store_domain, subject, message, status, escalated_from_ai, created_at')
    .order('created_at', { ascending: false })
    .limit(100);

  const filter = $('ticket-filter').value;
  if (filter === 'ai') query = query.eq('escalated_from_ai', true);
  else if (filter !== 'all') query = query.eq('status', filter);

  const { data, error } = await query;
  if (error) {
    setStatus(status, `Could not load tickets: ${error.message}`, true);
    return;
  }
  if (!data.length) {
    setStatus(status, 'No tickets match this filter.');
    return;
  }
  setStatus(status, `${data.length} ticket(s).`);

  data.forEach((ticket) => {
    const row = el('tr');

    const select = el('select', { 'aria-label': 'Ticket status' });
    TICKET_STATUSES.forEach((value) => {
      const option = el('option', { value }, value.replace('_', ' '));
      if (value === ticket.status) option.selected = true;
      select.appendChild(option);
    });
    select.addEventListener('change', () => changeTicketStatus(ticket.id, select.value, select));

    const statusCell = el('td');
    statusCell.appendChild(select);

    row.append(
      el('td', {}, formatTime(ticket.created_at)),
      el('td', {}, ticket.store_domain || '—'),
      el('td', {}, ticket.subject),
      el('td', {}, ticket.message),
      statusCell,
      el('td', {}, ticket.escalated_from_ai ? 'From AI chat' : 'Direct')
    );
    body.appendChild(row);
  });
}

async function changeTicketStatus(id, nextStatus, select) {
  const status = $('support-status');
  const { error } = await supabase
    .from('support_tickets')
    .update({ status: nextStatus })
    .eq('id', id);
  if (error) {
    setStatus(status, `Could not update the ticket: ${error.message}`, true);
    await loadTickets();
    return;
  }
  await audit('ticket_status:' + nextStatus, id);
  setStatus(status, 'Ticket updated.');
  select.blur();
}

// ---------- notice queue

async function loadNotices() {
  const status = $('notice-status');
  const body = $('notice-rows');
  body.replaceChildren();
  setStatus(status, 'Loading…');

  const { data, error } = await supabase
    .from('notice_reviews')
    .select('id, target_url, original_url, score, status, decided_by, created_at')
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) {
    setStatus(status, `Could not load notices: ${error.message}`, true);
    return;
  }
  if (!data.length) {
    setStatus(status, 'No notices waiting for review.');
    return;
  }
  setStatus(status, `${data.length} notice(s).`);

  data.forEach((notice) => {
    const row = el('tr');
    const decision = el('td');

    if (notice.status === 'ready') {
      const approve = el('button', { type: 'button', class: 'btn btn-primary' }, 'Approve');
      const reject = el('button', { type: 'button', class: 'btn btn-ghost' }, 'Reject');
      approve.addEventListener('click', () => decideNotice(notice.id, 'approved'));
      reject.addEventListener('click', () => decideNotice(notice.id, 'rejected'));
      decision.append(approve, ' ', reject);
    } else if (notice.status === 'approved') {
      const send = el('button', { type: 'button', class: 'btn btn-primary' }, 'Send notice');
      send.addEventListener('click', () => sendNotice(notice.id));
      decision.append(send);
    } else {
      decision.textContent = notice.decided_by
        ? `${notice.status} by ${notice.decided_by}`
        : notice.status;
    }

    const scoreText = notice.score == null ? 'manual' : `${Number(notice.score).toFixed(1)}%`;
    row.append(
      el('td', {}, formatTime(notice.created_at)),
      el('td', { class: 'mono' }, notice.target_url),
      el('td', { class: 'mono' }, notice.original_url),
      el('td', {}, scoreText),
      el('td', {}, notice.status),
      decision
    );
    body.appendChild(row);
  });
}

async function decideNotice(id, decision) {
  const status = $('notice-status');
  // Only a notice still waiting for review can be decided, so a double click can't change it twice.
  const { data, error } = await supabase
    .from('notice_reviews')
    .update({ status: decision, decided_by: adminEmail, decided_at: new Date().toISOString() })
    .eq('id', id)
    .eq('status', 'ready')
    .select('id');
  if (error) {
    setStatus(status, `Could not record the decision: ${error.message}`, true);
    return;
  }
  if (!data || !data.length) {
    setStatus(status, 'This notice was already decided. Refreshing.', true);
    await loadNotices();
    return;
  }
  await audit(`notice:${decision}`, id);
  setStatus(status, `Notice ${decision}.`);
  await loadNotices();
}

async function sendNotice(id) {
  const status = $('notice-status');
  const confirmed = window.confirm(
    'Send this takedown notice now? It is sent in the name of AlphaGuard and cannot be recalled. Continue only if the evidence has been reviewed.'
  );
  if (!confirmed) return;

  setStatus(status, 'Sending…');
  try {
    const session = await getCurrentSession();
    const token = session?.access_token;
    if (!token) throw new Error('Sign in again to send notices.');
    const response = await fetch(`/api/v1/admin/notices/${id}/send`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Send failed (HTTP ${response.status}).`);
    setStatus(status, 'Notice sent.');
  } catch (err) {
    setStatus(status, err.message || 'Could not send the notice.', true);
  }
  await loadNotices();
}

// ---------- authorizations (needs a consent table; shows the empty state until one exists)

async function loadAuthorizations() {
  const status = $('auth-status');
  $('auth-rows').replaceChildren();
  setStatus(status, 'No consent table is connected yet, so there are no authorization records to show.');
}

// ---------- audit log

async function loadAudit() {
  const status = $('audit-status');
  const body = $('audit-rows');
  body.replaceChildren();
  setStatus(status, 'Loading…');

  const { data, error } = await supabase
    .from('admin_audit_log')
    .select('actor, action, target_id, created_at')
    .order('created_at', { ascending: false })
    .limit(200);
  if (error) {
    setStatus(status, `Could not load the audit log: ${error.message}`, true);
    return;
  }
  if (!data.length) {
    setStatus(status, 'No actions recorded yet.');
    return;
  }
  setStatus(status, `${data.length} entr${data.length === 1 ? 'y' : 'ies'}.`);

  data.forEach((entry) => {
    const row = el('tr');
    row.append(
      el('td', {}, formatTime(entry.created_at)),
      el('td', {}, entry.actor),
      el('td', {}, entry.action),
      el('td', { class: 'mono' }, entry.target_id || '')
    );
    body.appendChild(row);
  });
}

// ---------- wiring

function bind() {
  document.querySelectorAll('[data-tab]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const tab = btn.dataset.tab;
      showTab(tab);
      if (tab === 'support') await loadTickets();
      if (tab === 'notices') await loadNotices();
      if (tab === 'auth') await loadAuthorizations();
      if (tab === 'audit') await loadAudit();
    });
  });
  document.querySelectorAll('[data-refresh]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const which = btn.dataset.refresh;
      if (which === 'support') loadTickets();
      if (which === 'notices') loadNotices();
      if (which === 'audit') loadAudit();
    });
  });
  $('ticket-filter').addEventListener('change', loadTickets);
  $('sign-out').addEventListener('click', async () => {
    await handleSignOut().catch(() => {});
    window.location.href = 'index.html';
  });
}

async function init() {
  bind();
  $('admin-clock').textContent = new Date().toLocaleDateString();
  const ok = await checkAccess();
  if (ok) await loadTickets();
}

init();