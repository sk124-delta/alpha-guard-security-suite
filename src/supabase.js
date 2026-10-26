const SUPABASE_URL = "https://gorfvxahnpvplnmxlfqx.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdvcmZ2eGFobnB2cGxubXhsZnF4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTI4MjA1MDIsImV4cCI6MjEwODM5NjUwMn0.yYHGw5lo0VgClOAJutp3O3oUp6XgPXpYdGl7WCm7atY";

if (SUPABASE_URL === "YOUR_SUPABASE_URL" || SUPABASE_ANON_KEY === "YOUR_SUPABASE_ANON_KEY") {
  throw new Error("Set SUPABASE_URL and SUPABASE_ANON_KEY in src/supabase.js before using Supabase.");
}

if (!window.supabase?.createClient) {
  throw new Error("The Supabase JavaScript CDN library did not load.");
}

export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export async function handleSignUp(email, password, fullName) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { full_name: fullName } },
  });

  if (error) {
    console.error("Signup error:", error.message);
    throw error;
  }
  return data;
}

export async function handlePasswordReset(email) {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: "https://www.alphaguardsuite.com/update-password.html",
  });

  if (error) {
    console.error("Supabase reset error:", error.message);
    throw error;
  }
}
