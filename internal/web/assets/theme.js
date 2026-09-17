/*
  The colour scheme switch, and nothing else.

  Loaded in the head of every page, before anything is drawn, so a reader who
  chose a scheme is never shown the other one first. The page follows the
  system until the switch is used; then it remembers "light" or "dark" in this
  browser's local storage, which is the one thing any page here stores. It is
  never sent anywhere: the server does not read it and nothing in it names a
  person or a host.

  No markup is built here and nothing a server sends is read, which is why this
  is a file of its own rather than part of app.js: a page that runs no check
  loads this and nothing else.
*/

"use strict";

(function () {
  const KEY = "theme";
  const root = document.documentElement;

  function stored() {
    try {
      const value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" ? value : null;
    } catch {
      // Storage refused (a private window, a policy). The system decides.
      return null;
    }
  }

  function current() {
    const chosen = stored();
    if (chosen) return chosen;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  const initial = stored();
  if (initial) root.dataset.theme = initial;

  function label(button) {
    // Says what pressing it does, not what is showing.
    button.textContent = current() === "dark" ? "Light" : "Dark";
    button.setAttribute("aria-label",
      current() === "dark" ? "Switch to the light colour scheme" : "Switch to the dark colour scheme");
  }

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.hidden = false;
    label(button);

    button.addEventListener("click", () => {
      const next = current() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        window.localStorage.setItem(KEY, next);
      } catch {
        // Not remembered, and still switched for this page.
      }
      label(button);
    });
  });
})();
