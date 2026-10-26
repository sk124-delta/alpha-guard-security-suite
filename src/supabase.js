const SUPABASE_URL = "YOUR_SUPABASE_URL";
const SUPABASE_ANON_KEY = "YOUR_SUPABASE_ANON_KEY";

if (SUPABASE_URL === "YOUR_SUPABASE_URL" || SUPABASE_ANON_KEY === "YOUR_SUPABASE_ANON_KEY") {
  throw new Error("Set SUPABASE_URL and SUPABASE_ANON_KEY in src/supabase.js before using Supabase.");
}

if (!window.supabase?.createClient) {
  throw new Error("The Supabase JavaScript CDN library did not load.");
}

export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export async function handlePasswordReset(email) {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: "https://www.alphaguardsuite.com/update-password.html",
  });

  if (error) {
    console.error("Error sending password reset:", error.message);
    throw error;
  }
}
