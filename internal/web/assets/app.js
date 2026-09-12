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

/*
  One script, three checks.

  The pages differ in four things: which endpoint they call, which method page
  their standing limits point at, what the button says while it waits, and how
  a report is drawn. Everything else — the builders, the verdict handling, the
  findings, the notes, the download, the failure path, the counter — is the
  same work and is written once. Two scripts would be two copies of all of it,
  and the copy nobody is looking at is the one that falls behind.

  Which check a page is comes from the page rather than from the path, because
  a path is a thing that moves. The form carries it in a data attribute, which
  the markup can set and the CSP cannot object to; there is no inline script
  anywhere on this site and this does not add one.
*/
const CHECKS = {
  tls: {
    label: "Transport",
    says: "the handshake and the certificate behind it",
    endpoint: "/api/v1/tls/scan",
    methodPage: "/tls/method",
    working: "Opening handshakes at every TLS version. This takes a few seconds.",
    build: (data) => buildTLS(data),
  },
  web: {
    label: "Reach",
    says: "how the site is reached over HTTP and HTTPS",
    endpoint: "/api/v1/web/scan",
    methodPage: "/web/method",
    working: "Reading how the site answers, over HTTPS and over plaintext.",
    build: (data) => buildWeb(data),
  },
  mail: {
    label: "Mail",
    says: "what the domain's DNS says about its mail",

    // No method page of its own yet. The console prints the standing limits
    // in full rather than pointing at a page nobody has written, which is the
    // same decision the command line made — a URL for a page that does not
    // exist is worse than no URL, because a reader follows it.
    endpoint: "/api/v1/mail/scan",
    methodPage: "",
    working: "Reading the sender policy, the DMARC record, the mail exchangers and what protects them.",
    build: (data) => buildMail(data),
  },
};

// The order the console runs and draws them in.
//
// Fixed rather than taken from the object, because a report whose sections
// move between two scans of an unchanged estate is a diff a reader has to work
// out is not a change.
const CHECK_ORDER = ["tls", "web", "mail"];

// Defaulting to the TLS check rather than to nothing, because a page that
// declared no check would otherwise fail at the first click with an error
// about undefined rather than about anything a reader could act on.
const CHECK = CHECKS[(form && form.dataset.check) || "tls"] || CHECKS.tls;

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

// Saving a report, entirely in the browser.
//
// Nothing is asked of the service again and nothing is kept anywhere: the JSON
// already arrived, and this hands the reader the bytes they already have. A
// server endpoint returning the same thing would have to keep the result or
// scan a second time, and this project does neither.
//
// JSON and nothing else, which is a security decision rather than a
// preference. Every string in a report — subjects, names, issuers — is chosen
// by the server that was scanned, and each of the other formats hands those
// strings to something that executes them. A spreadsheet reads a value
// beginning with =, +, - or @ as a formula. A terminal reads an escape
// sequence in a name as an instruction and rewrites what is already on the
// screen, which is a defect this project found in its own command line output.
// A browser reads HTML as markup. JSON escapes a control byte as \u001b and
// carries no executable meaning anywhere, so the format itself is the
// protection rather than something bolted onto it.

// Not the clipboard, and that is a decision rather than an omission.
//
// A clipboard button reads as the same offer and is not. The system clipboard
// is shared with every process on the machine, Windows keeps a history of it
// that any of them can read, and a cloud clipboard sends it off the machine
// entirely. A file goes to one place the reader chose and no further.
//
// What is sensitive in a report is not its contents — everything in it is
// public and was sent by the server to anyone who connected. It is that
// somebody asked about that host. This service undertakes to keep no record
// of what was scanned, by whom or when, and handing that fact to a channel
// every application can read would undo the promise on the reader's side of
// it. Offering both would not be a convenience; it would be the weaker of the
// two, offered without saying so.

// The object URL for the report on screen, and only ever one.
//
// An object URL keeps its blob alive for as long as the document does, so the
// previous one is released before the next is made: a reader who scans twenty
// hosts holds one report in memory rather than twenty.
let reportURL = null;

function downloadLink(data) {
  if (reportURL) {
    URL.revokeObjectURL(reportURL);
    reportURL = null;
  }

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  reportURL = URL.createObjectURL(blob);

  // A link rather than a button driving a synthetic click: it can be
  // right-clicked, opened in a new tab, and read by anything that reads links.
  const anchor = el("a", "download", "Download as JSON");
  anchor.href = reportURL;
  anchor.download = reportFilename(data);
  return anchor;
}

// reportFilename builds a name from the target.
//
// The target reaching here is already canonical — the service accepts letters,
// digits, dot, hyphen, underscore and colon in a hostname and nothing else —
// so this is a second fence rather than the first. A colon is legal in an IPv6
// target and illegal in a Windows filename; anything outside the set becomes a
// hyphen; and the whole is cut short, because a name that can be made long is
// a name that ends up somewhere it does not fit.
function reportFilename(data) {
  // The TLS report names a host and port; the web report names a bare host.
  // One filename builder, because a reader saving one of each should get two
  // files named the same way.
  const target = String((data && (data.target || data.host)) || "report").toLowerCase();
  const safe = target
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 60);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  return "denyfirst-" + (safe || "report") + "-" + stamp + "Z.json";
}

function summary(data) {
  const wrap = el("div", "summary");

  // The verdict and the thing it is a verdict on, on one line.
  //
  // Until 2026-09-01 the two sentences below were in this row too, inside the
  // left column. A dl is a block, so the column took the whole width and the
  // stamp — the first thing anybody looks for — wrapped to a line of its own
  // underneath four lines of coverage, below the sentence that explains it.
  // A verdict that arrives after its explanation is a verdict read twice.
  const head = el("div", "summary-head");

  const left = el("div");
  left.appendChild(el("p", "summary-target", data.target || data.host || data.domain || "—"));

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
  left.appendChild(downloadLink(data));

  head.appendChild(left);

  const verdict = verdictOf(data);
  const stamp = el("div", "stamp " + verdictClass("stamp", verdict), verdict);
  if (!data.verdict) stamp.textContent = "not graded";
  head.appendChild(stamp);

  wrap.appendChild(head);

  // What a weak or insecure verdict means, under the verdict.
  //
  // The report's likeliest misreading: a red stamp sits next to a trusted
  // chain, a verified staple, transparency, CAA and an accepted post-quantum
  // group, and nothing on the page says why one option outweighs all of that.
  // The sentence is built in internal/policy so that both faces say it in the
  // same words. R16.
  if (verdict === "weak" || verdict === "insecure") {
    wrap.appendChild(el("p", "summary-worst", WORST_CASE));
  }

  // How much of the picture this scan reached, which is what the verdict
  // rests on and what no table says.
  //
  // Labelled, in the same grammar as the certificate rows and the cipher
  // facts. Unlabelled it arrived directly beneath the worst-case sentence and
  // the two read as one paragraph — and an unlabelled sentence under a table
  // is exactly what made the key exchange invisible until somebody looked
  // twice.
  if (data.coverage) {
    const reached = el("dl", "pairs summary-pairs");
    reached.appendChild(el("dt", null, "Coverage"));
    reached.appendChild(el("dd", "summary-coverage", data.coverage));
    wrap.appendChild(reached);
  }

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

function ciphers(tls, report) {
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

    // One geometry for every cipher table, and a container that scrolls.
    //
    // Each version gets its own table, and until 2026-09-02 each sized its own
    // columns to its own contents: measured on a live report, "Key exchange"
    // began 92 pixels further right under TLS 1.2 than under TLS 1.3, and
    // "Cipher" 68 to the left. Two tables, one above the other, the same four
    // columns, and a reader's eye could not run down one of them. Nothing was
    // wrong with any row; the page simply could not be read the way a table
    // exists to be read.
    //
    // Declared widths make the columns the same everywhere, and a scrolling
    // container keeps them that way on a narrow screen instead of breaking a
    // forty-five character suite name across three lines.
    const table = el("table", "rows suites");

    // The geometry is declared on the columns, not left to the contents.
    //
    // A <colgroup> is the one place a table can be told how wide its columns
    // are before any row is read, and it is what makes two tables one above
    // the other line up. The stylesheet gives three of them a width and lets
    // the suite names take what is left.
    //
    // Written out one at a time rather than looped over a list, because the
    // test that checks every class the script writes has a rule behind it
    // reads class names out of el() calls. A class assembled from a variable
    // is invisible to it, and a column with no rule is a column with no
    // width.
    const group = el("colgroup");
    group.appendChild(el("col", "col-grade"));
    group.appendChild(el("col", "col-suite"));
    group.appendChild(el("col", "col-kex"));
    group.appendChild(el("col", "col-cipher"));
    table.appendChild(group);

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
    frag.appendChild(el("div", "table-scroll")).appendChild(table);
  }

  // Labelled rather than left as prose.
  //
  // These sat under the table with nothing in front of them, and the key
  // exchange — the one measurement that costs the scanned server an extra
  // handshake — was read on a second visit rather than the first. The
  // certificate rows are found because they carry a label; these now do too.
  //
  // They stay with the suites and not with the certificate. A key exchange is
  // a property of the transport: the certificate's key is RSA 4096 and the
  // exchange is X25519MLKEM768, and filing one under the other teaches a
  // reader they are the same thing.
  const facts = el("dl", "pairs");
  let said = false;

  function fact(label, value) {
    if (!value) return;
    facts.appendChild(el("dt", null, label));
    facts.appendChild(el("dd", null, value));
    said = true;
  }

  if (tls.preferenceKnown) {
    fact("Cipher order", tls.serverPreference
      ? "the server imposes its own"
      : "the client's, which lets an outdated client choose a weaker suite");
  }
  if (report && report.keyExchangeLine) {
    fact("Key exchange", report.keyExchangeLine);
  }
  if (said) frag.appendChild(facts);

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
  // What the issuer says it checked. Next to the issuer because that is whose
  // claim it is, and above the dates because it is about how the certificate
  // came to exist rather than about how long it lasts.
  pair("Validation", leaf.validation);

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

  // What the public logs hold for this name, where a deployment searched them.
  // Absent where none did, which is this one: the sentence is composed in
  // internal/policy and arrives empty when no search was made, so nothing here
  // decides whether to show it.
  pair("Logged", report && report.loggedLine);

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
// What a weak or insecure verdict means.
//
// Written here and in internal/policy, and compared by a test that reads both
// — the same arrangement as the section titles below. A sentence about how
// grading works, said in two different words on two faces of one report,
// would be worse than not saying it at all.
const WORST_CASE = "Worst case: an attacker chooses which option to negotiate, " +
  "so the weakest one a server accepts is the one that decides.";

// The three sections, their order and their words. The terminal report reads
// the same three from noteSections in cmd/denyfirst-scan, and the two are
// compared by a test: a reader holding one output beside the other should not
// have to work out that they match.
const NOTE_SECTIONS = [
  {
    kind: "observed",
    title: "Observed",

    // Folded, and this is safe because of what is in it.
    //
    // Every fact an observation describes is already on the face of the
    // report: the key exchange line says the hybrid was declined, the
    // revocation row says nothing was stapled, the issuance row says no CAA
    // was found, the certificate rows carry the names and the timestamps.
    // What folds is the reasoning behind them, which is the same on every
    // report and is what made this block five paragraphs long.
    //
    // The count stays in the summary, so folding is not hiding. The
    // coverage line under the verdict says how much of the picture the scan
    // reached, which is the thing a reader would otherwise open this for.
    open: false,
    // Not "findings". The report uses that word for a rule that was broken
    // and says, three lines above this, that there were none — so "5 findings
    // not graded" asked a reader to hold two meanings of one word at once.
    one: "1 measured, not graded",
    many: (n) => n + " measured, not graded",
  },
  {
    kind: "unsettled",
    title: "Not established for this host",
    open: false,
    one: "1 limit",
    many: (n) => n + " limits",
  },
];

// The third kind is a link, not a section.
//
// A standing limit is the same on every report, so showing them all on every
// report is how they stop being read — and sitting beside a host's own
// shortcomings they read as though they were some. They are on one page, and
// the report says how many there are and points at it, so moving them is not
// hiding them.
// Which page, per check: what a TLS handshake cannot establish is not what a
// header check cannot establish, and a link that pointed at one from the other
// would send a reader to limits that are not theirs.
const METHOD_PAGE = CHECK.methodPage;

// notes renders each kind under its own heading.
//
// Until 2026-09-01 there was one heading — "What this did not measure" — over
// everything that was not a finding. A scan of kapitalbank.az put eleven
// sentences under it, of which three were limits of that scan. Among the rest
// was a post-quantum key exchange that had been measured and had passed, and
// a stapled revocation response that had been read and verified. A reader who
// trusted the heading concluded the scanner had established almost nothing,
// which is the opposite of what the report contained.
//
// Both sections fold. Every fact in them is already on the face of the
// report, so what folds is the reasoning; the counts stay in the summaries,
// and an ungraded verdict opens them because then there is nothing else.
function notes(list, verdict) {
  const frag = document.createDocumentFragment();
  if (!list || !list.length) return frag;

  for (const section of NOTE_SECTIONS) {
    const chosen = list.filter((n) => n && n.kind === section.kind);
    if (!chosen.length) continue;

    // A literal class, not one built from the kind. internal/web reads the
    // classes this script adds straight out of its source and checks each one
    // is styled; a class assembled at runtime is invisible to that check, and
    // an unstyled class is exactly what it exists to catch. The three sections
    // differ by their words and by which of them opens, not by their colour.
    const box = el("details", "notes-section");
    // An ungraded verdict means something was not reached, so the reasons are
    // opened rather than left behind a summary.
    box.open = section.open || verdict === "ungraded";

    const head = el("summary", "notes-head");
    head.appendChild(el("span", "notes-title", section.title));
    head.appendChild(el("span", "notes-count",
      chosen.length === 1 ? section.one : section.many(chosen.length)));
    box.appendChild(head);

    const ul = el("ul", "notes");
    for (const note of chosen) ul.appendChild(el("li", null, note.text));
    box.appendChild(ul);

    frag.appendChild(box);
  }

  const standing = list.filter((n) => n && n.kind === "standing");
  if (standing.length) {
    const p = el("p", "notes-method");
    // Two of the four limits are conditional, so a report can carry one: a
    // host that speaks only TLS 1.2 and returns no transparency receipts
    // leaves exactly one, and the page said "1 limits".
    p.appendChild(document.createTextNode(standing.length === 1
      ? "1 limit of this method applies to every scan and is the same here as anywhere. "
      : standing.length + " limits of this method apply to every scan and are the same here as anywhere. "));

    const a = el("a", "notes-method-link", "What this can see, and what it cannot");
    a.href = METHOD_PAGE;
    p.appendChild(a);

    frag.appendChild(p);
  }

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

function buildTLS(data) {
  // Read once. data.verdict is absent rather than "ungraded" when nothing was
  // graded, so every section that cares has to be given the resolved value —
  // passing data.verdict straight through would hand them undefined at
  // exactly the moment the distinction matters most.
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(summary(data));
  frag.appendChild(findings(data.findings, verdict));
  frag.appendChild(versions(data.tls));
  frag.appendChild(ciphers(data.tls, data));
  frag.appendChild(certificate(data.certificate, data.tls, data.issuance, data.stapling, data));
  frag.appendChild(notes(data.notes, verdict));
  return frag;
}

/*
  The web report: two chains, drawn the same way.

  A chain is the sequence of addresses a browser would be sent through,
  starting at the secure address and starting again at the plaintext one. It is
  the whole evidence behind the verdict, so it is on the face of the report
  rather than folded away — a reader who cannot see where a site sent them
  cannot check the grade against anything.

  Both chains get identical columns, because they are the same measurement
  begun at two addresses and a reader comparing them should not have to work
  out which column moved (W3).
*/

// hopTransport says how a hop was made, in a word.
//
// In words rather than only in colour. A reader who cannot distinguish the two
// colours, or who prints the page, has to be able to read the one fact this
// column exists for (W6).
function hopTransport(hop) {
  if (hop.tls) return "TLS";
  return "plaintext";
}

// hopOutcome is what came back, or why nothing did.
//
// A hop that failed is not a response with no headers, and the difference
// decides a verdict rather than a detail: a host answering 200 in the clear is
// insecure, and a host with nothing listening on port 80 is the safest
// arrangement there is (R23). So a failure says so in its own words rather
// than appearing as a blank status.
function hopOutcome(hop) {
  const cell = el("td", hop.error ? "mark-faint" : null);
  if (hop.error) {
    cell.appendChild(el("span", null, "no response"));
    // The reason is a phrase webprobe wrote, never a string from the standard
    // library, so it carries no address of this machine (I6). It still reaches
    // textContent rather than a parser, like everything else here.
    cell.appendChild(el("p", "row-note", hop.error));
    return cell;
  }
  cell.appendChild(el("span", null, String(hop.status || "—")));
  return cell;
}

function chain(title, c) {
  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle(title));

  if (!c || !Array.isArray(c.hops) || !c.hops.length) {
    // Nothing attempted is not nothing found. Saying so is the same rule R4
    // states for a verdict, applied to a table.
    frag.appendChild(el("p", "plain", "Nothing was attempted at this address."));
    return frag;
  }

  const table = el("table", "rows");
  const head = el("tr");
  for (const label of ["Address", "Transport", "Response"]) {
    head.appendChild(el("th", null, label));
  }
  table.appendChild(el("thead")).appendChild(head);

  const body = el("tbody");
  for (const hop of c.hops) {
    const row = el("tr");
    // The address as it was requested. Attacker-chosen after the first hop —
    // every one after it came out of a Location header — so it is text in a
    // cell and never a link: a redirect target this scanner declined to follow
    // must not become something a reader can click.
    row.appendChild(el("td", null, hop.url || "—"));
    row.appendChild(el("td", null, hopTransport(hop)));
    row.appendChild(hopOutcome(hop));
    body.appendChild(row);
  }
  table.appendChild(body);
  frag.appendChild(table);

  // Where a chain stopped, and whether stopping was a decision or a failure.
  // A reader who cannot tell those apart cannot interpret the chain at all
  // (N7).
  if (c.truncated) {
    frag.appendChild(el("p", "group-note",
      "The redirect limit was reached with another address still waiting, so this chain is " +
      "incomplete and nothing should be concluded from where it stops."));
  }
  if (c.stopped) {
    frag.appendChild(el("p", "group-note", "This chain was not followed further: " + c.stopped));
  }

  return frag;
}

function chains(observed) {
  const frag = document.createDocumentFragment();
  if (!observed) return frag;

  frag.appendChild(chain("Reached over HTTPS", observed.secure));
  frag.appendChild(chain("Reached over plaintext", observed.plain));

  // What was sent, said on the report rather than only on the method page.
  // The user agent is recorded so that a report says how it was obtained
  // instead of asking a reader to trust a document.
  if (observed.userAgent) {
    const p = el("p", "group-note");
    p.appendChild(document.createTextNode("Requested as " + observed.userAgent + ". "));
    const a = el("a", "notes-method-link", "What was sent, in full");
    a.href = CHECK.methodPage;
    p.appendChild(a);
    frag.appendChild(p);
  }

  return frag;
}

function buildWeb(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(summary(data));
  frag.appendChild(findings(data.findings, verdict));
  frag.appendChild(chains(data.observed));
  frag.appendChild(notes(data.notes, verdict));
  return frag;
}

/*
  The mail report: what the zone says, and what it costs to evaluate.

  Two rows of evidence rather than a chain, because there is no chain — nothing
  was connected to. The lookup count is on the face of the report rather than
  only in the notes, since it is the number this check exists for: a domain at
  nine of ten is one provider away from switching its own policy off, and no
  other tool an operator runs will tell them.
*/
function buildMail(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(summary(data));
  frag.appendChild(findings(data.findings, verdict));
  frag.appendChild(zone(data.observed));
  frag.appendChild(notes(data.notes, verdict));
  return frag;
}

// zone draws what the three lookups established.
//
// Every value here is written by this program from booleans and counts, never
// pasted from the zone: a record's text is chosen by whoever is being measured,
// and the sentences a reader acts on should not be.
function zone(facts) {
  const frag = document.createDocumentFragment();
  if (!facts) return frag;

  frag.appendChild(sectionTitle("What the zone says"));

  const table = el("table", "grid");
  const body = el("tbody");

  const row = (name, value, mark) => {
    const tr = el("tr");
    tr.appendChild(el("th", null, name));
    const td = el("td", mark ? markClass(mark) : null, value);
    tr.appendChild(td);
    body.appendChild(tr);
  };

  // SPF, and the three states that are not "a policy was read".
  if (facts.spfReason) {
    row("SPF", "not read: " + facts.spfReason);
  } else if (!facts.spfRecords) {
    row("SPF", "none published");
  } else if (facts.spfRecords > 1) {
    row("SPF", facts.spfRecords + " records, which is a permanent error", "insecure");
  } else {
    row("SPF", "ends in " + (facts.spfAll || "no ") + "all");
    row(
      "Lookups",
      facts.spfLookups + " of the ten RFC 7208 allows",
      facts.spfLookupLimit ? "insecure" : null,
    );
  }

  if (facts.dmarcReason) {
    row("DMARC", "not read: " + facts.dmarcReason);
  } else if (!facts.dmarcRecords) {
    row("DMARC", "none published");
  } else if (facts.dmarcRecords > 1) {
    row("DMARC", facts.dmarcRecords + " records, so a receiver applies none", "weak");
  } else if (!facts.dmarcPolicy) {
    row("DMARC", "published, and names no policy", "weak");
  } else {
    row("DMARC", "p=" + facts.dmarcPolicy + " at " + (facts.dmarcPercent || 0) + "%");
  }

  row("TLS-RPT", facts.tlsReporting ? "yes" : "no");

  // Where the mail goes, and what protects it there.
  //
  // Three states kept apart on every line, because the difference is the whole
  // value: a domain with no DANE, a domain whose DANE could not be read, and a
  // domain that accepts no mail at all are three answers a reader acts on
  // differently, and a table that drew them alike would be worse than silent.
  if (facts.mxReason) {
    row("MX", "not read: " + facts.mxReason);
  } else if (facts.nullMX) {
    row("MX", "null MX: the domain accepts no mail");
  } else if (!facts.mxRead) {
    row("MX", "not read");
  } else {
    const hosts = facts.mxHosts || [];
    row("MX", hosts.length ? hosts.join(", ") : "none published");

    row("MTA-STS", facts.mtaStsRecords
      ? "announced; the policy itself was not fetched"
      : "no");

    if (hosts.length) {
      const dane = facts.daneHosts || [];
      if (dane.length === 0) {
        row("DANE", "none of the " + hosts.length);
      } else if (dane.length === hosts.length) {
        row("DANE", "all " + hosts.length);
      } else {
        row("DANE", dane.length + " of the " + hosts.length + ": " + dane.join(", "));
      }
    }
    if (facts.daneUnread) {
      row("DANE", facts.daneUnread + " could not be read");
    }
  }

  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

// ── Submission ──────────────────────────────────────────────────────────

async function check(target, spec) {
  spec = spec || CHECK;
  // Addressed under the check it runs, like the page it is called from.
  //
  // /api/v1/scan is still served and answers identically, because a path in
  // somebody's script is not a link they can be redirected from: a redirect
  // on a POST is followed by some clients and dropped by others, and a body
  // that quietly goes nowhere is worse than a path that stays.
  const response = await fetch(spec.endpoint, {
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

if (form) form.addEventListener("submit", async event => {
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
  show(el("p", "working", CHECK.working));

  try {
    show(CHECK.build(await check(target)));
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
// ── The console ─────────────────────────────────────────────────────────

/*
  One target, several checks, one report.

  This is the surface a self-hosted installation puts at "/", and it is a
  different thing from the pages at /tls and /web rather than a prettier
  version of them. Those explain a check to somebody who arrived from a log
  line. This runs an estate's checks for the person who runs the estate, and
  the two audiences want opposite things: one wants the argument, the other
  wants the answer and the evidence under it.

  What it is not is a second renderer. Every section here is built by the same
  functions the single-check pages call, from the same JSON, so a sentence
  cannot say one thing on one page and something else on the other — which is
  R16, and which this project has already had to fix twice.

  Sequential rather than parallel, for two reasons. Each check spends a token
  from the scanned host's budget, and three at once from one page is the shape
  the budget exists to discourage. And a section that appears as it finishes is
  a page that is doing something, where three that appear together after nine
  seconds is a page that looks broken.
*/
const consoleForm = document.getElementById("console-form");
const consoleTarget = document.getElementById("console-target");
const consoleButton = document.getElementById("console-submit");
const consoleResults = document.getElementById("console-results");

// selectedChecks reads the boxes, in the order the console draws them.
function selectedChecks() {
  const boxes = document.querySelectorAll("input[name='check']");
  const chosen = new Set();
  boxes.forEach(box => {
    if (box.checked && CHECKS[box.value]) chosen.add(box.value);
  });
  return CHECK_ORDER.filter(name => chosen.has(name));
}

// consoleSection is one check's block: a heading that says which check and
// how it ended, and room for the report underneath.
function consoleSection(spec) {
  const section = el("section", "run");

  const head = el("div", "run-head");
  head.appendChild(el("h2", "run-name", spec.label));
  head.appendChild(el("p", "run-says", spec.says));

  const state = el("p", "run-state", "running");
  head.appendChild(state);
  section.appendChild(head);

  const body = el("div", "run-body");
  section.appendChild(body);

  return { section, state, body };
}

/*
  A check that could not run says so in its own section and stops nothing.

  The whole reason the runs are separate. A domain with no mail policy at all,
  a host that refuses a handshake, a name this deployment has not been shown
  control of — each of those is an answer about one check, and letting it end
  the other two would turn one refusal into a blank page. An operator reading
  "Transport: strong, Mail: refused" knows exactly where they stand; an
  operator reading nothing does not.
*/
async function runCheck(name, target) {
  const spec = CHECKS[name];
  const { section, state, body } = consoleSection(spec);
  consoleResults.appendChild(section);

  body.appendChild(el("p", "working", spec.working));

  try {
    const data = await check(target, spec);
    clear(body);
    body.appendChild(spec.build(data));

    const verdict = verdictOf(data);
    state.textContent = data.verdict ? verdict : "not graded";
    state.className = "run-state " + verdictClass("stamp", verdict);
    return verdict;
  } catch (err) {
    clear(body);

    const hint = err.status === 429
      ? "Wait a moment before trying again. Each host has its own budget, whoever asks."
      : err.status === 503
        ? "Several scans are running. Try again shortly."
        : null;

    body.appendChild(failure(err.message || "The check did not complete.", hint));
    state.textContent = "not run";
    state.className = "run-state stamp-ungraded";
    return null;
  }
}

if (consoleForm) {
  consoleForm.addEventListener("submit", async event => {
    event.preventDefault();

    const target = consoleTarget.value.trim();
    if (!target) {
      clear(consoleResults);
      consoleResults.hidden = false;
      consoleResults.appendChild(failure("Enter a hostname to check."));
      consoleTarget.focus();
      return;
    }

    const chosen = selectedChecks();
    if (chosen.length === 0) {
      clear(consoleResults);
      consoleResults.hidden = false;
      consoleResults.appendChild(failure("Choose at least one check."));
      return;
    }

    consoleButton.disabled = true;
    const label = consoleButton.textContent;
    consoleButton.textContent = "Checking";

    clear(consoleResults);
    consoleResults.hidden = false;

    try {
      // Awaited one at a time on purpose. See the note above.
      for (const name of chosen) {
        await runCheck(name, target);
      }
    } finally {
      consoleButton.disabled = false;
      consoleButton.textContent = label;
    }
  });
}
