/*
  denyfirst
  ---------
  Every node on this page is built with createElement and textContent.
  innerHTML, insertAdjacentHTML, document.write and outerHTML appear nowhere,
  and a test in internal/web asserts that they never will.

  The reason is specific rather than general. A successful scan returns the
  target the caller sent, by design, and hostnames are attacker-chosen. The
  moment that value reaches a markup parser it stops being data. Building
  nodes directly means there is no parser to reach: a string assigned to
  textContent is a string, whatever it contains.
*/

"use strict";

const form = document.getElementById("scan-form");
const input = document.getElementById("target");
const button = document.getElementById("submit");
const result = document.getElementById("result");

const VERDICT_ORDER = { insecure: 3, weak: 2, strong: 1 };

// ── Small builders ──────────────────────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function link(href, text) {
  const a = document.createElement("a");
  // Only http and https are ever rendered. Anything else — javascript:, data:
  // — is shown as plain text instead, so a hostile source list in a response
  // cannot become a clickable script.
  const safe = typeof href === "string" && /^https?:\/\//i.test(href);
  if (!safe) return el("span", null, text);

  a.href = href;
  a.textContent = text;
  a.rel = "noopener noreferrer";
  a.target = "_blank";
  return a;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function verdictClass(prefix, verdict) {
  const known = ["strong", "weak", "insecure"];
  return prefix + "-" + (known.includes(verdict) ? verdict : "ungraded");
}

// ── Sections ────────────────────────────────────────────────────────────

function sectionTitle(text) {
  return el("h2", "section-title", text);
}

// The verdict as the page should treat it. The field is omitted from the
// response when nothing could be graded, and an absent value is not the same
// as an unknown one: it means the scan reached nothing.
function verdictOf(data) {
  return data && data.verdict ? data.verdict : "ungraded";
}

function summary(data) {
  const wrap = el("div", "summary");

  const left = el("div");
  left.appendChild(el("p", "summary-target", data.target || "—"));

  const address = data.tls && data.tls.address;
  const meta = [];
  if (address) meta.push(address);
  // The negotiated application protocol, when one was agreed. It costs a
  // word and answers a question a reader would otherwise open a terminal
  // for. Attacker-chosen, like every other value here, and reaching
  // textContent rather than a parser for the same reason.
  if (data.tls && data.tls.alpn) meta.push(data.tls.alpn);
  if (data.policy) meta.push("graded by " + data.policy);
  if (meta.length) left.appendChild(el("p", "summary-meta", meta.join("  ·  ")));

  wrap.appendChild(left);

  const verdict = verdictOf(data);
  const stamp = el("div", "stamp " + verdictClass("stamp", verdict), verdict);
  if (!data.verdict) stamp.textContent = "not graded";
  wrap.appendChild(stamp);

  return wrap;
}

function findings(list, verdict) {
  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Findings"));

  if (!list || list.length === 0) {
    // An empty list means two entirely different things and the difference is
    // the one this project exists to insist on.
    //
    // After a scan that reached the server, it means nothing fell short. After
    // one that reached nothing — a name that does not resolve, a port that
    // refused every version — it means there was nothing to fall short of, and
    // saying "nothing fell short of the rules" there reads as a pass. It is
    // true and it is misleading, which is the worst combination a report can
    // manage.
    frag.appendChild(el("p", "finding-body", verdict === "ungraded"
      ? "Nothing was measured, so nothing could be graded. This is not a clean result; it is an absent one."
      : "Nothing here fell short of the rules."));
    return frag;
  }

  const sorted = list.slice().sort(
    (a, b) => (VERDICT_ORDER[b.verdict] || 0) - (VERDICT_ORDER[a.verdict] || 0)
  );

  for (const f of sorted) {
    const item = el("div", "finding " + verdictClass("finding", f.verdict));

    const head = el("div", "finding-head");
    head.appendChild(el("h3", "finding-title", f.title || "Untitled finding"));
    if (f.ruleId) head.appendChild(el("span", "finding-rule", f.ruleId));
    item.appendChild(head);

    if (f.rationale) item.appendChild(el("p", "finding-body", f.rationale));

    if (Array.isArray(f.references) && f.references.length) {
      const sources = el("div", "sources");
      for (const ref of f.references) {
        sources.appendChild(link(ref.url, ref.label || ref.url));
      }
      item.appendChild(sources);
    }

    frag.appendChild(item);
  }

  return frag;
}

function versions(tls) {
  if (!tls || !Array.isArray(tls.versions)) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Protocol versions"));

  const table = el("table", "rows");
  const head = el("tr");
  for (const label of ["Version", "Offered", "Grade"]) {
    head.appendChild(el("th", null, label));
  }
  table.appendChild(el("thead")).appendChild(head);

  const body = el("tbody");
  for (const v of tls.versions) {
    const row = el("tr");
    row.appendChild(el("td", null, v.name));
    row.appendChild(el("td", v.supported ? null : "mark-faint", v.supported ? "accepted" : "refused"));

    const grade = v.supported && v.grade ? v.grade.verdict : "";
    const cell = el("td", grade ? "mark-" + grade : "mark-faint",
      grade ? (v.grade.preferred ? grade + "  ·  preferred" : grade) : "—");
    row.appendChild(cell);

    body.appendChild(row);
  }
  table.appendChild(body);
  frag.appendChild(table);

  return frag;
}

function ciphers(tls) {
  if (!tls || !Array.isArray(tls.versions)) return document.createDocumentFragment();

  const offered = tls.versions.filter(v => v.supported && Array.isArray(v.ciphers) && v.ciphers.length);
  if (!offered.length) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Cipher suites accepted"));

  for (const v of offered) {
    frag.appendChild(el("p", "group-label", v.name));

    const table = el("table", "rows");
    const head = el("tr");
    for (const label of ["Grade", "Suite", "Key exchange", "Cipher"]) {
      head.appendChild(el("th", null, label));
    }
    table.appendChild(el("thead")).appendChild(head);

    const body = el("tbody");
    for (const c of v.ciphers) {
      const row = el("tr");
      row.appendChild(el("td", "mark-" + (c.verdict || "faint"), c.verdict || "—"));
      // Marked so the stylesheet may break this column mid-word on a narrow
      // screen without doing the same to the short labels beside it.
      row.appendChild(el("td", "identifier", c.name));
      row.appendChild(el("td", "mark-faint", c.keyExchange || "—"));
      row.appendChild(el("td", "mark-faint", c.cipher || "—"));
      body.appendChild(row);
    }
    table.appendChild(body);
    frag.appendChild(table);
  }

  if (tls.preferenceKnown) {
    frag.appendChild(el("p", "group-label", tls.serverPreference
      ? "The server imposes its own cipher order."
      : "The server follows the client's order, which lets an outdated client choose a weaker suite."));
  }

  return frag;
}

// The four states a reader has to be able to tell apart. Returns undefined
// when the report says nothing about revocation, so the row is left out
// entirely rather than filled with a guess.
function revocationText(revocation, tls) {
  if (!revocation) return undefined;

  const stapled = !!(tls && tls.ocspStapled);
  const mustStaple = !!revocation.mustStaple;
  const responders = Number(revocation.responderCount) || 0;

  if (mustStaple && !stapled) {
    return "the certificate requires a stapled response and none was sent";
  }
  if (mustStaple) return "stapled, and the certificate requires it";
  if (stapled) return "a status response was stapled";
  if (responders > 0) {
    return "not stapled; the certificate names a responder a client would have to ask";
  }
  return "not stapled; the certificate names no responder, so there is none to send";
}

// Two numbers, because one cannot answer the question.
//
// Browsers ask for receipts from several distinct logs, so that one log
// misbehaving cannot satisfy the requirement alone. Three receipts from one
// log and three from three are different situations and a single count cannot
// tell them apart. Returns undefined when the report says nothing, so the row
// is left out rather than filled with a guess.
function transparencyText(transparency, tls) {
  if (!transparency) return undefined;

  const embedded = Number(transparency.embeddedCount) || 0;
  const logs = Number(transparency.logCount) || 0;
  const handshake = Number(tls && tls.sctCount) || 0;
  const total = embedded + handshake;

  if (total === 0) return "no timestamps in the certificate or the handshake";

  const stamps = total === 1 ? "1 timestamp" : total + " timestamps";
  const from = logs === 1 ? "1 log" : logs + " logs";
  const where = handshake > 0 && embedded > 0
    ? " (" + embedded + " embedded, " + handshake + " in the handshake)"
    : "";

  return stamps + " from " + from + where + ", not verified";
}

function certificate(cert, tls) {
  if (!cert || !Array.isArray(cert.chain) || !cert.chain.length) {
    return document.createDocumentFragment();
  }

  const leaf = cert.chain[0];
  const grade = cert.grade || {};

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Certificate"));

  const pairs = el("dl", "pairs");

  function pair(label, value) {
    if (value === undefined || value === null || value === "") return;
    pairs.appendChild(el("dt", null, label));
    pairs.appendChild(el("dd", null, value));
  }

  pair("Subject", leaf.subject);
  pair("Issuer", leaf.issuer);

  const from = (leaf.notBefore || "").slice(0, 10);
  const to = (leaf.notAfter || "").slice(0, 10);
  if (from && to) {
    const days = grade.daysRemaining;
    let life = from + " to " + to;
    if (typeof days === "number") {
      life += days >= 0 ? "  ·  " + days + " days left" : "  ·  expired " + (-days) + " days ago";
    }
    pair("Valid", life);
  }

  if (grade.validityDays) {
    pair("Lifetime", grade.validityDays + " days, limit at issuance " + grade.maxValidityDays);
  }

  pair("Key", leaf.keyBits ? leaf.keyAlgorithm + " " + leaf.keyBits : leaf.keyAlgorithm);
  pair("Signature", leaf.signatureAlgorithm);

  if (Array.isArray(leaf.dnsNames) && leaf.dnsNames.length) {
    pair("Names", leaf.dnsNames.join(", "));
  }

  pair("Chain", cert.chain.length + (cert.trusted ? " certificates, trusted" : " certificates, not trusted"));

  // What the certificate asks for, and what the handshake carried.
  //
  // Four states rather than a tick. "Not stapled" alone reads as a fault,
  // and for a certificate issued now it usually is not one: authorities are
  // no longer required to run OCSP, and several have stopped. The
  // distinction between a server that could staple and did not and one that
  // has nothing to staple is the whole content of this line.
  pair("Revocation", revocationText(cert.revocation, tls));
  pair("Transparency", transparencyText(cert.transparency, tls));
  pair("SHA-256", leaf.fingerprintSha256);

  frag.appendChild(pairs);
  return frag;
}

/*
  What was not measured, kept in proportion to how much it matters.

  A reader who is not told what was skipped will read silence as a clean
  result, so this is never omitted. But three paragraphs of caveat under a
  clean report is its own kind of noise, and a reader who meets it every time
  stops reading it — which produces the same silence by a longer route.

  So the summary is always visible and always counts them, and the detail
  opens on request. Except where it is the whole story: a report that graded
  nothing has nothing else to say, and there the limits are the finding.

  That exception was once extended to an insecure verdict as well, and the
  reasoning above never covered it. A report that graded a server insecure
  has findings, a version table, a cipher list and a certificate: the limits
  are a footnote there exactly as they are under a strong verdict, and
  opening them by default said otherwise. Nothing is hidden either way —
  the count sits in the summary line whether the block is open or shut.
*/
function notes(list, verdict) {
  if (!list || !list.length) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  const alwaysOpen = verdict === "ungraded";

  const box = el("details", "not-measured");
  box.open = alwaysOpen;

  const head = el("summary", "not-measured-head");
  head.appendChild(el("span", "not-measured-title", "What this did not measure"));
  head.appendChild(el("span", "not-measured-count",
    list.length === 1 ? "1 limit" : list.length + " limits"));
  box.appendChild(head);

  const ul = el("ul", "notes");
  for (const note of list) ul.appendChild(el("li", null, note));
  box.appendChild(ul);

  frag.appendChild(box);
  return frag;
}

function failure(message, detail) {
  const box = el("div", "failure");
  box.appendChild(el("p", null, message));
  if (detail) box.appendChild(el("p", null, detail));
  return box;
}

// ── Rendering ───────────────────────────────────────────────────────────

function show(node) {
  clear(result);
  result.hidden = false;
  result.appendChild(node);
}

function render(data) {
  // Read once. data.verdict is absent rather than "ungraded" when nothing was
  // graded, so every section that cares has to be given the resolved value —
  // passing data.verdict straight through would hand them undefined at
  // exactly the moment the distinction matters most.
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(summary(data));
  frag.appendChild(findings(data.findings, verdict));
  frag.appendChild(versions(data.tls));
  frag.appendChild(ciphers(data.tls));
  frag.appendChild(certificate(data.certificate, data.tls));
  frag.appendChild(notes(data.notes, verdict));
  show(frag);
}

// ── Submission ──────────────────────────────────────────────────────────

async function check(target) {
  const response = await fetch("/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: target }),
    // The hostname is in the body rather than the URL so it stays out of
    // browser history and out of proxy logs. Sending no referrer keeps it out
    // of anything the page links to afterwards.
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });

  let body = null;
  try {
    body = await response.json();
  } catch {
    throw new Error("The server sent something this page could not read.");
  }

  if (!response.ok) {
    const error = body && body.error ? body.error : {};
    const err = new Error(error.message || "The scan did not complete.");
    err.code = error.code;
    err.status = response.status;
    throw err;
  }

  return body;
}

form.addEventListener("submit", async event => {
  event.preventDefault();

  const target = input.value.trim();
  if (!target) {
    show(failure("Enter a hostname to check."));
    input.focus();
    return;
  }

  button.disabled = true;
  const label = button.textContent;
  button.textContent = "Checking";
  show(el("p", "working", "Opening handshakes at every TLS version. This takes a few seconds."));

  try {
    render(await check(target));
  } catch (err) {
    const hint = err.status === 429
      ? "Wait a moment before trying again."
      : err.status === 503
        ? "Several scans are running. Try again shortly."
        : null;
    show(failure(err.message || "The scan did not complete.", hint));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
});
// ── The counter ─────────────────────────────────────────────────────────

/*
  Shown because a number nobody can trace back to a person is the clearest
  demonstration of the claim on this page. Saying "nothing is recorded" is a
  promise; publishing the only thing that is recorded, and letting a reader
  see it holds no hostname, no address and no time, is closer to a proof.
*/
async function showTally() {
  const tally = document.getElementById("tally");
  if (!tally) return;

  try {
    const response = await fetch("/api/v1/stats", { cache: "no-store" });
    if (!response.ok) return;

    const stats = await response.json();
    if (typeof stats.scansTotal !== "number" || stats.scansTotal < 1) return;

    const total = stats.scansTotal.toLocaleString("en");
    let since = "";
    if (typeof stats.since === "string" && /^\d{4}-\d{2}-\d{2}$/.test(stats.since)) {
      const date = new Date(stats.since + "T00:00:00Z");
      if (!isNaN(date)) {
        since = " since " + date.toLocaleDateString("en", {
          day: "numeric", month: "long", year: "numeric", timeZone: "UTC",
        });
      }
    }

    tally.textContent =
      total + " scans" + since + ". The only trace any of them left.";
    tally.hidden = false;
  } catch {
    // A missing counter is not worth an error on the page.
  }
}

showTally();