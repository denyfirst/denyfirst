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

/*
  Every class name on this page comes from this list and nowhere else.

  Nothing a caller sends reaches a class attribute today: a verdict is written
  by internal/policy, and the API returns one of four fixed strings. So this is
  not closing a hole that is open. It closes the one that opens the first time
  somebody builds a class out of a field that is attacker-chosen, which is one
  line and no warning — a class name is not a script, but it decides what the
  page looks like, and a page that will paste any string into a class attribute
  has handed its appearance to whoever answers.

  It was already done in one place and not in two others, and the difference
  was invisible from either.
*/
const VERDICTS = ["strong", "weak", "insecure"];

function verdictClass(prefix, verdict) {
  return prefix + "-" + (VERDICTS.includes(verdict) ? verdict : "ungraded");
}

// The table cells use their own prefix and fall back to a neutral colour
// rather than to an "ungraded" one, because a blank cell is not a verdict.
function markClass(verdict) {
  return VERDICTS.includes(verdict) ? "mark-" + verdict : "mark-faint";
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

/*
  What happened at this version, in the words the probe used.

  This cell said "accepted" or "refused" and nothing else, and the second word
  was wrong more often than it was right. Only one kind of failure is a
  refusal: the server answered and declined. Our own client not offering the
  version, a name that did not resolve, a timeout, a reset, a connection the
  service would not make — all of them leave `supported` false as well, and
  all of them were printed as "refused".

  The direction of that error is what makes it worth a fix rather than a note.
  A row reading "TLS 1.0  refused" is a row in the server's favour: refusing an
  obsolete version is the correct configuration, and the page was crediting
  servers with it on the strength of a handshake that never happened. The
  server may well still accept TLS 1.0.

  The API carries both halves — `refused` says which kind, `error` says what
  happened — and neither was read here.
*/
function outcomeCell(v) {
  const cell = el("td", v.supported ? null : "mark-faint");
  cell.appendChild(el("span", null,
    v.supported ? "accepted" : (v.refused ? "refused" : "not measured")));
  if (!v.supported && v.error) cell.appendChild(el("p", "row-note", v.error));
  return cell;
}

function versions(tls) {
  if (!tls || !Array.isArray(tls.versions)) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Protocol versions"));

  const table = el("table", "rows");
  const head = el("tr");
  // "Outcome" rather than "Offered". The column has never held an answer to
  // "was it offered" — it holds what happened, and one of the three things it
  // can now say is that nothing did.
  for (const label of ["Version", "Outcome", "Grade"]) {
    head.appendChild(el("th", null, label));
  }
  table.appendChild(el("thead")).appendChild(head);

  const body = el("tbody");
  for (const v of tls.versions) {
    const row = el("tr");
    row.appendChild(el("td", null, v.name));
    row.appendChild(outcomeCell(v));

    const grade = v.supported && v.grade ? v.grade.verdict : "";
    const cell = el("td", markClass(grade),
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

    // Beside the list rather than only in the folded notes at the foot.
    //
    // "Cipher suites accepted" over a list that stopped early reads as the
    // whole set, and the suites missing from it are the weak ones —
    // enumeration finds them strongest first. The note that says so is
    // counted in the summary line but the block is shut under every verdict
    // except ungraded, so under a weak or insecure verdict the reader is
    // looking at a truncated table with nothing on it to say so.
    //
    // Negated rather than compared to false: an absent field is treated as an
    // incomplete list, so a response that forgets to say gets the cautious
    // reading. That is the same polarity the Go field was given.
    if (!v.cipherListComplete) {
      frag.appendChild(el("p", "group-note",
        "This list is incomplete. The host stopped answering before enumeration ran out, "
        + "and suites are found strongest first, so what is missing is the weaker end."));
    }

    const table = el("table", "rows");
    const head = el("tr");
    for (const label of ["Grade", "Suite", "Key exchange", "Cipher"]) {
      head.appendChild(el("th", null, label));
    }
    table.appendChild(el("thead")).appendChild(head);

    const body = el("tbody");
    for (const c of v.ciphers) {
      const row = el("tr");
      row.appendChild(el("td", markClass(c.verdict), c.verdict || "—"));
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
// The revocation and transparency sentences used to be composed here, and only
// here. That put them out of reach of the terminal report, which showed
// neither, and out of reach of anything that could execute them: the
// revocation sentence went on saying "a status response was stapled" for a
// whole policy version after the service had begun parsing that response,
// matching it to the certificate, checking its freshness and verifying the
// issuer's signature.
//
// They are built in internal/policy now, arrive as report.revocationLine and
// report.transparencyLine, and are printed here unchanged. Do not compose a
// sentence in this file from facts the report already carries a sentence for:
// two renderers building one claim is how the two come to disagree. R16.

function certificate(cert, tls, issuance, stapling, report) {
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
  pair("Revocation", report && report.revocationLine);

  // Issuance sits above transparency because the two are halves of one
  // question in the order they happen: who may obtain a certificate for this
  // name, and whether obtaining one leaves a record. A restriction is checked
  // when a certificate is issued; the logs record the result either way.
  //
  // It is on a line of its own rather than in the notes, which fold shut
  // under every verdict but ungraded. For a name with no CAA this is often
  // the most useful sentence in the report — one DNS record, nothing to break
  // by adding it — and a sentence nobody opens is a sentence nobody reads.
  pair("Issuance", issuance && issuance.line);
  pair("Transparency", report && report.transparencyLine);
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
  frag.appendChild(certificate(data.certificate, data.tls, data.issuance, data.stapling, data));
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