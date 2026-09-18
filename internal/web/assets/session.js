/*
  Signing in, signing out and changing the password, and nothing else.

  A file of its own because the pages that need it are every page behind a
  password, and most of them load no other script: History in particular
  serves no result and runs nothing that could fetch one. This asks the
  session endpoints and moves the browser; it reads no report and stores
  nothing. The session itself is a cookie the server sets, which no script
  here can read.
*/

"use strict";

(function () {
  async function send(method, path, body) {
    const response = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
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
      const problem = await send("POST", "/api/v1/session", { password: field.value });
      if (problem === null) {
        window.location.assign("/");
        return;
      }
      status.textContent = problem;
      field.value = "";
      field.focus();
      button.disabled = false;
    });
  }

  const signOut = document.getElementById("sign-out");
  if (signOut) {
    signOut.addEventListener("click", async () => {
      signOut.disabled = true;
      await send("DELETE", "/api/v1/session");
      window.location.assign("/login");
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
      const problem = await send("POST", "/api/v1/password", { password: current.value, next: next.value });
      status.textContent = problem === null
        ? "Changed. Every other session has been signed out."
        : problem;
      current.value = "";
      if (problem === null) {
        next.value = "";
        again.value = "";
      }
      button.disabled = false;
    });
  }
})();
