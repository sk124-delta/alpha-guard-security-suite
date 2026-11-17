// Supabase authentication for AlphaGuard.
// The Supabase library is loaded by a <script> tag in index.html (before app.js).
// If the library or config is missing, the rest of the site still works and auth calls
// fail with a clear message instead of breaking the page.

const SUPABASE_URL = 'https://gorfvxahnpvplnmxlfqx.supabase.co';
// Anon key only. It is designed to be public; access control comes from Row Level Security.
// Never place the service_role key in client code.
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdvcmZ2eGFobnB2cGxubXhsZnF4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI4MjA1MDIsImV4cCI6MjEwODM5NjUwMn0.yYHGw5lo0VgClOAJutp3O3oUp6XgPXpYdGl7WCm7atY';

const CONFIG_OK = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY && !SUPABASE_URL.includes('YOUR_'));
const LIBRARY_OK = typeof window !== 'undefined' && Boolean(window.supabase?.createClient);

const isLocalHost = typeof window !== 'undefined'
  && ['localhost', '127.0.0.1'].includes(window.location.hostname);

export const RESET_REDIRECT_URL = isLocalHost
  ? `${window.location.origin}/update-password`
  : 'https://www.alphaguardsuite.com/update-password';

let client = null;
if (CONFIG_OK && LIBRARY_OK) {
  client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      flowType: 'pkce',
      storage: window.localStorage,
    },
  });
} else {
  console.error(
    'Sign-in is unavailable: ' +
    (!CONFIG_OK ? 'Supabase config is missing. ' : '') +
    (!LIBRARY_OK ? 'The Supabase library did not load. Check the script tag in index.html.' : '')
  );
}

export const authReady = client !== null;
export const supabase = client;

const UNAVAILABLE = 'Sign-in is temporarily unavailable. Please try again later.';

function requireClient() {
  if (!client) throw new Error(UNAVAILABLE);
  return client;
}

function authError(error, fallback) {
  console.error(fallback, error?.message || error);
  const err = new Error(error?.message || fallback);
  err.cause = error;
  throw err;
}

export async function handleSignUp(email, password, fullName, storeUrl) {
  const sb = requireClient();
  const { data, error } = await sb.auth.signUp({
    email,
    password,
    options: {
      data: {
        full_name: fullName,
        store_name: fullName,
        store_url: storeUrl || '',
      },
    },
  });
  if (error) authError(error, 'Signup error:');
  return data;
}

export async function handleSignIn(email, password) {
  const sb = requireClient();
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) authError(error, 'Sign-in error:');
  return data;
}

export async function handleSignOut() {
  const sb = requireClient();
  const { error } = await sb.auth.signOut();
  if (error) authError(error, 'Sign-out error:');
}

export async function handlePasswordReset(email) {
  const sb = requireClient();
  const { error } = await sb.auth.resetPasswordForEmail(email, {
    redirectTo: RESET_REDIRECT_URL,
  });
  if (error) authError(error, 'Supabase reset error:');
}

export async function getCurrentSession() {
  if (!client) return null; // no session can exist without the client; the page shows signed-out
  const { data, error } = await client.auth.getSession();
  if (error) authError(error, 'Session error:');
  return data.session || null;
}

export function onAuthStateChange(callback) {
  if (!client) return null;
  const { data } = client.auth.onAuthStateChange((_event, session) => {
    callback(session);
  });
  return data?.subscription || null;
}

export async function updatePassword(password) {
  const sb = requireClient();
  const { data, error } = await sb.auth.updateUser({ password });
  if (error) authError(error, 'Password update error:');
  return data;
}

export async function exchangeRecoveryCode(code) {
  const sb = requireClient();
  const { data, error } = await sb.auth.exchangeCodeForSession(code);
  if (error) authError(error, 'Recovery code error:');
  return data;
}