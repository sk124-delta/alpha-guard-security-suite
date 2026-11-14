const SUPABASE_URL = "https://gorfvxahnpvplnmxlfqx.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdvcmZ2eGFobnB2cGxubXhsZnF4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI4MjA1MDIsImV4cCI6MjEwODM5NjUwMn0.yYHGw5lo0VgClOAJutp3O3oUp6XgPXpYdGl7WCm7atY";

if (SUPABASE_URL === "YOUR_SUPABASE_URL" || SUPABASE_ANON_KEY === "YOUR_SUPABASE_ANON_KEY") {
  throw new Error("Set SUPABASE_URL and SUPABASE_ANON_KEY in src/supabase.js before using Supabase.");
}

if (!window.supabase?.createClient) {
  throw new Error("The Supabase JavaScript CDN library did not load.");
}

const isLocalHost = ["localhost", "127.0.0.1"].includes(window.location.hostname);
export const RESET_REDIRECT_URL = isLocalHost
  ? `${window.location.origin}/update-password`
  : "https://www.alphaguardsuite.com/update-password";

export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    flowType: "pkce",
    storage: window.localStorage,
  },
});

function authError(error, fallback) {
  console.error(fallback, error?.message || error);
  const err = new Error(error?.message || fallback);
  err.cause = error;
  throw err;
}

export async function handleSignUp(email, password, fullName, storeUrl) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        full_name: fullName,
        store_name: fullName,
        store_url: storeUrl || "",
      },
    },
  });

  if (error) authError(error, "Signup error:");
  return data;
}

export async function handleSignIn(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) authError(error, "Sign-in error:");
  return data;
}

export async function handleSignOut() {
  const { error } = await supabase.auth.signOut();
  if (error) authError(error, "Sign-out error:");
}

export async function handlePasswordReset(email) {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: RESET_REDIRECT_URL,
  });
  if (error) authError(error, "Supabase reset error:");
}

export async function getCurrentSession() {
  const { data, error } = await supabase.auth.getSession();
  if (error) authError(error, "Session error:");
  return data.session || null;
}

export function onAuthStateChange(callback) {
  return supabase.auth.onAuthStateChange((_event, session) => {
    callback(session);
  });
}

export async function updatePassword(password) {
  const { data, error } = await supabase.auth.updateUser({ password });
  if (error) authError(error, "Password update error:");
  return data;
}

export async function exchangeRecoveryCode(code) {
  const { data, error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) authError(error, "Recovery code error:");
  return data;
}
