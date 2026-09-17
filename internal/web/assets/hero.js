/*
  The lens over the front page's opening, and nothing else.

  Where the pointer rests, a dim circle opens on what is under the surface: a
  faint grid of points and a few quiet words. It is decoration,
  so it asks for nothing and keeps nothing. The pointer's position inside the
  opening is written to two custom properties on one element and read by the
  stylesheet; it is not stored, not sent, and gone when the page is.

  It does nothing where it would be a nuisance or meaningless: for a reader
  who asked for less motion, and on a screen without a pointer that hovers.
  There the opening is drawn as it is without this file.
*/

"use strict";

(function () {
  const hero = document.querySelector(".hero");
  const lens = hero && hero.querySelector(".hero-lens");
  if (!lens || !window.matchMedia) return;
  if (!window.matchMedia("(hover: hover) and (pointer: fine)").matches) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  // One write per frame, however often the pointer reports.
  let frame = 0;
  let x = 0;
  let y = 0;

  hero.addEventListener("pointermove", (event) => {
    const box = hero.getBoundingClientRect();
    x = event.clientX - box.left;
    y = event.clientY - box.top;
    hero.classList.add("hero-lit");
    if (frame) return;
    frame = window.requestAnimationFrame(() => {
      frame = 0;
      lens.style.setProperty("--lens-x", x + "px");
      lens.style.setProperty("--lens-y", y + "px");
    });
  });

  hero.addEventListener("pointerleave", () => hero.classList.remove("hero-lit"));
})();
