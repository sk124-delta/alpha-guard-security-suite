import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-analytics.js";
import {
  confirmPasswordReset,
  createUserWithEmailAndPassword,
  deleteUser,
  getAuth,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
} from "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyBllcj_LWuS2GmhKgAzdqPba5QoqxhPc2g",
  authDomain: "alpha-guard-security-suite.firebaseapp.com",
  projectId: "alpha-guard-security-suite",
  storageBucket: "alpha-guard-security-suite.firebasestorage.app",
  messagingSenderId: "293859702668",
  appId: "1:293859702668:web:f0cd16316e752d901288a9",
  measurementId: "G-0KZ773NVYV",
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const analytics = getAnalytics(app);
export { createUserWithEmailAndPassword, signInWithEmailAndPassword };

const passwordResetActionCodeSettings = {
  url: "https://www.alphaguardsuite.com/update-password",
  handleCodeInApp: true,
};

export async function sendPasswordReset(email) {
  try {
    await sendPasswordResetEmail(auth, email, passwordResetActionCodeSettings);
  } catch (error) {
    console.error("Password reset request failed:", error.code, error.message, error);
    throw error;
  }
}

export async function submitNewPassword(newPassword) {
  const oobCode = new URLSearchParams(window.location.search).get("oobCode");
  if (!oobCode) {
    throw new Error("This reset link is invalid or incomplete. Please request a new one.");
  }
  await confirmPasswordReset(auth, oobCode, newPassword);
}

export async function removeFirebaseUser(user) {
  try {
    await deleteUser(user);
  } catch (error) {
    console.error("Could not roll back Firebase user:", error.message);
  }
}

export async function handleSignup(email, password) {
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    console.info("User signed up successfully.");
    return userCredential;
  } catch (error) {
    console.error("Error signing up:", error.message);
    throw error;
  }
}