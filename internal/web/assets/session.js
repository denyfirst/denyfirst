/*
  Signing in, signing out and changing the password, and nothing else.

  A file of its own because the pages that need it are every page behind a
  password, and most of them load no other script: History in particular
  serves no result and runs nothing that could fetch one. This asks the
  session endpoints and moves the browser; it reads no report and stores
  nothing. The session itself is a cookie the server sets, which no script
  here can read.

  Every form gets its button back and says what happened, whatever the
  answer: an error, something that is not JSON, no answer at all. A network
  that fails left the buttons disabled and "Checking…" on screen (audit
  2026-09-18, D07), and a sign-out the server never saw sent the browser to
  the sign-in page as though it had.
*/

"use strict";

(function () {
  // How long an answer is waited for before it is treated as none.
  const WAIT = 15000;

  // send returns null when the installation said yes, and otherwise the
  // sentence to show. It never throws.
  async function send(method, path, body) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), WAIT);
    let response;
    try {
      response = await fetch(path, {
        method,
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
        credentials: "same-origin",
        signal: abort.signal,
      });
    } catch {
      return "The installation could not be reached. Nothing here can say whether it acted; try again.";
    } finally {
      clearTimeout(timer);
    }
    if (response.ok) return null;
    let message = "The installation did not answer as expected.";
    try {
      const data = await response.json();
      if (data && data.error && typeof data.error.message === "string") message = data.error.message;
    } catch {
      // Not JSON; the generic sentence stands.
    }
    return message;
  }

  const signinForm = document.getElementById("signin-form");
  if (signinForm) {
    const field = document.getElementById("signin-password");
    const button = document.getElementById("signin-submit");
    const status = document.getElementById("signin-status");
    signinForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      status.textContent = "Checking…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/session", { password: field.value });
      } finally {
        if (problem === null) {
          window.location.assign("/");
        } else {
          status.textContent = problem;
          field.value = "";
          field.focus();
          button.disabled = false;
        }
      }
    });
  }

  // Signed out means the server said it ended the session. Until it does,
  // the session may still be good, so the browser stays where it is and the
  // button says it did not work rather than showing the sign-in page, which
  // would look the same as success.
  const signOut = document.getElementById("sign-out");
  if (signOut) {
    signOut.addEventListener("click", async () => {
      signOut.disabled = true;
      signOut.textContent = "Signing out…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("DELETE", "/api/v1/session");
      } finally {
        if (problem === null) {
          window.location.assign("/login");
        } else {
          signOut.textContent = "Not signed out. Try again";
          signOut.title = problem;
          signOut.disabled = false;
        }
      }
    });
  }

  const passwordForm = document.getElementById("password-form");
  if (passwordForm) {
    const current = document.getElementById("password-current");
    const next = document.getElementById("password-next");
    const again = document.getElementById("password-again");
    const button = document.getElementById("password-submit");
    const status = document.getElementById("password-status");
    passwordForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (next.value !== again.value) {
        status.textContent = "The two new passwords are not the same.";
        return;
      }
      button.disabled = true;
      status.textContent = "Saving…";
      let problem = "The installation did not answer as expected.";
      try {
        problem = await send("POST", "/api/v1/password", { password: current.value, next: next.value });
      } finally {
        status.textContent = problem === null
          ? "Changed. Every other session has been signed out."
          : problem;
        current.value = "";
        if (problem === null) {
          next.value = "";
          again.value = "";
        }
        button.disabled = false;
      }
    });
  }
})();
