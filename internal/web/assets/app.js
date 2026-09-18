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

    endpoint: "/api/v1/mail/scan",
    methodPage: "/mail/method",
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

// The demonstration says so on its body. A few things an installation offers
// its operator mean nothing there: a download of a report about our own
// domain, and a count of our own checks.
const DEMO_SITE = document.body.dataset.site === "demo";

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
  if (data.policy) meta.push("graded by " + data.policy);
  if (meta.length) left.appendChild(el("p", "summary-meta", meta.join("  ·  ")));
  // Not on the demonstration: a report there is about our own domain, and a
  // visitor has no use for a copy of it. A copy of your own is where a
  // download matters, because nothing is kept for you.
  if (!DEMO_SITE) left.appendChild(downloadLink(data));

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
  // The reason only where it says something the word does not. Beside
  // "refused" it repeated it — "refused  server refused TLS 1.0" — and the
  // SSL 3.0 row, which carries no such sentence, read differently from the
  // rows above it.
  if (!v.supported && !v.refused && v.error) cell.appendChild(el("p", "row-note", v.error));
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

  // SSL 3.0, asked with a hand-written hello because Go's client cannot speak
  // it. Beside the other versions and in the same three words, so a reader
  // scanning the list for the obsolete one finds it where they look — and
  // "refused" only where the server said no (R4).
  const ssl3 = tls.legacy && tls.legacy.asked ? tls.legacy.ssl3 : null;
  if (ssl3) {
    const row = el("tr");
    row.appendChild(el("td", null, "SSL 3.0"));
    row.appendChild(outcomeCell({ supported: ssl3.accepted, refused: ssl3.refused, error: ssl3.reason }));
    // The suite it was accepted with goes here too, since this is now the
    // only row SSL 3.0 has.
    const grade = ssl3.accepted && ssl3.versionGrade ? ssl3.versionGrade.verdict : "";
    const suite = ssl3.accepted && ssl3.suite ? "  ·  " + ssl3.suite.name : "";
    row.appendChild(el("td", markClass(grade), grade ? grade + suite : "—"));
    body.appendChild(row);
  }

  table.appendChild(body);
  frag.appendChild(table);

  return frag;
}

// What the hand-written hellos were answered with.
//
// The same rows the terminal prints, in the same order and words (R16). Titled
// as asked by hand, because these are not an enumeration: each is one hello
// offering every suite of a family at once, and "export: refused" means none of
// them was accepted by that hello, not that each was tried.
// What each of the name's addresses answered when asked on its own.
//
// The same rows and the same words as printAddresses in the command line (R16).
// Whether they agree is said once, in the notes.
function addresses(tls) {
  const list = tls && tls.addresses;
  if (!list || !list.length) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  frag.appendChild(sectionTitle("Each address, asked on its own"));

  const table = el("table", "rows");
  const body = el("tbody");
  for (const a of list) {
    const row = el("tr");
    row.appendChild(el("td", null, a.address));
    row.appendChild(el("td", a.answered ? null : "mark-faint", addressSays(a)));
    body.appendChild(row);
  }
  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

function addressSays(a) {
  if (!a.answered) return "no answer: " + a.reason;
  const cert = a.certificate ? a.certificate.slice(0, 16) + "…" : "none presented";
  return a.version + " " + a.suite + ", certificate " + cert;
}

function legacy(tls) {
  const l = tls && tls.legacy;
  if (!l || !l.asked) return document.createDocumentFragment();

  const frag = document.createDocumentFragment();
  // What this section is, said under its title. It read as a second list of
  // versions with SSL 3.0 in it twice; it is the suite families the ordinary
  // enumeration cannot offer, each asked for in one hello of its own. SSL 3.0
  // is a version and stays in the version table.
  //
  // Why they are asked this way is the method page's to say, not the
  // report's: the note says how to read a row, and the link says the rest.
  frag.appendChild(sectionTitle("Obsolete suites, asked for directly"));
  const note = el("p", "section-note",
    "Each family was offered on its own, every suite in it at once. " +
    "Refused means the server accepted none of them. ");
  const why = el("a", "notes-method-link", "Why these are asked separately");
  why.href = CHECKS.tls.methodPage + "#obsolete-suites";
  note.appendChild(why);
  frag.appendChild(note);

  const table = el("table", "rows");
  const body = el("tbody");

  const answer = (label, a) => {
    const row = el("tr");
    row.appendChild(el("td", null, label));
    row.appendChild(outcomeCell({ supported: a.accepted, refused: a.refused, error: a.reason }));
    const suite = a.accepted && a.suite ? a.suite : null;
    row.appendChild(el("td", markClass(suite ? suite.verdict : ""),
      suite ? suite.verdict + "  ·  " + suite.name + " at " + a.version : "—"));
    body.appendChild(row);
  };
  // The same rows the terminal prints, in its words (R16). Named for what
  // each family is, because "export" and "NULL" alone meant nothing to a
  // reader who had not met them. Older reports carry neither ffdhe nor
  // anonymous, so each is drawn only where it was sent.
  answer("Export-grade", l.export);
  answer("NULL, no encryption", l.null);
  if (l.ffdhe) answer("Finite-field DHE", l.ffdhe);
  if (l.anonymous) answer("Anonymous, no certificate", l.anonymous);

  const f = l.fallback;
  const row = el("tr");
  row.appendChild(el("td", null, "Downgrade signal"));
  row.appendChild(el("td", f.measured ? null : "mark-faint",
    f.measured ? (f.honoured ? "honoured" : "not honoured") : "not measured"));
  row.appendChild(el("td", null, f.measured
    ? "a hello claiming only " + f.asked + (f.honoured ? " was refused" : " was answered")
    : f.reason));
  body.appendChild(row);

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

  // What Mozilla, Chrome, Microsoft and Apple make of the chain, in the words
  // certinfo wrote, which the terminal prints too (R16).
  if (cert.storesLine) pair("Stores", cert.storesLine);

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
// would send a reader to limits that are not theirs. So each builder passes its
// own. It was read from the page once, which held while a page ran one check;
// the Porch page runs three, and its Reach and Mail reports pointed at the
// limits of Transport.

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
function notes(list, verdict, methodPage) {
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
    a.href = methodPage;
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
  frag.appendChild(legacy(data.tls));
  frag.appendChild(addresses(data.tls));
  frag.appendChild(certificate(data.certificate, data.tls, data.issuance, data.stapling, data));
  frag.appendChild(notes(data.notes, verdict, CHECKS.tls.methodPage));
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

  // The user agent is not drawn. It is the same on every report, so it is a
  // line about this program rather than about the server, and the method
  // page states it with everything else that was sent; the report's limits
  // line links there. The field stays in the JSON, which is where a saved
  // report says how it was obtained, and the terminal never printed it.
  return frag;
}

function buildWeb(data) {
  const verdict = verdictOf(data);

  const frag = document.createDocumentFragment();
  frag.appendChild(summary(data));
  frag.appendChild(findings(data.findings, verdict));
  frag.appendChild(chains(data.observed));
  frag.appendChild(notes(data.notes, verdict, CHECKS.web.methodPage));
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
  frag.appendChild(notes(data.notes, verdict, CHECKS.mail.methodPage));
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
      (facts.spfLookupsAtLeast ? "at least " : "") + facts.spfLookups + " of the ten RFC 7208 allows",
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

  // Signing keys, and which names were looked under.
  //
  // Nothing found is never drawn as "no DKIM". DNS cannot list what is beneath
  // a name, so a scan only ever looked where it was told to look, and the
  // difference between "these names hold nothing" and "this domain publishes no
  // key" is the whole honesty of the section (R4).
  if (facts.dkimLooked) {
    const keys = facts.dkimKeys || [];
    const found = keys.filter(k => k.found);

    if (found.length) {
      row("DKIM", found.map(k => k.selector + " (" + k.describes + ")").join(", "));
    } else {
      row("DKIM", "none at the " + keys.length + " selectors tried");
    }
  } else {
    row("DKIM", "not checked: a selector has to be named");
  }


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

    row("MTA-STS", stsSays(facts));

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

    // What each exchanger answered when asked for encryption, in the words
    // the terminal uses (R16).
    if (hosts.length) {
      if (facts.exchangersContacted) {
        for (const x of facts.exchangers || []) {
          row("STARTTLS", x.host + ": " + exchangerSays(x));
        }
        for (const b of facts.daneBindings || []) {
          row("DANE", b.host + ": " + daneSays(b));
        }
      } else if (facts.exchangersReason) {
        row("STARTTLS", "not measured: " + facts.exchangersReason);
      }
    }
  }

  table.appendChild(body);
  frag.appendChild(table);
  return frag;
}

// What one exchanger's STARTTLS row says.
//
// The same five states and the same words as exchangerLine in the command line,
// because a reader comparing the two faces of one report should find one set of
// facts (R16).
function exchangerSays(x) {
  if (!x.measured && x.connectTimedOut) return "not measured: port 25 could not be reached from here";
  if (!x.measured) return "not measured: " + x.reason;
  if (!x.offered) return "not offered";
  if (!x.upgraded) return "offered, not negotiated: " + x.reason;
  if (!x.trusted) return x.version + " " + x.suite + ", certificate does not verify: " + x.certificateReason;
  if (!x.nameMatches) return x.version + " " + x.suite + ", certificate does not name this exchanger";
  return x.version + " " + x.suite + ", certificate verifies";
}

// What one exchanger's DANE records made of its certificate.
//
// The same words as daneLine in the command line (R16), and the same note when
// the resolver did not report the records validated: it decides whether a sender
// acts on any of it.
function daneSays(b) {
  let line;
  if (b.outcome === "matched") line = "matches the certificate presented";
  else if (b.outcome === "mismatched") line = "does not match: " + b.reason;
  else if (b.outcome === "no-starttls") line = "records published, STARTTLS not offered";
  else if (b.outcome === "no-usable-records") line = "no record a sender uses for SMTP";
  else line = "not established: " + b.reason;
  if (!b.validated) line += " (records not reported validated)";
  return line;
}

// What the MTA-STS row says.
//
// Four states, and the same four the terminal report draws — R16 says one
// result, two renderers, one set of facts, and the only way that holds for a
// sentence built by hand on each side is that somebody writes them together.
// This row said "announced; the policy itself was not fetched" for the whole
// life of the check, which covered a domain fully protected and a domain that
// had been rehearsing for two years, and those are the two readers most need
// told apart.
//
// A mode that was read is shown. A mode that was not is shown as not read, with
// the reason, because an empty mode drawn as a mode is the R4 failure this
// project keeps finding in other tools.
function stsSays(facts) {
  if (!facts.mtaStsRecords) {
    return "no";
  }
  if (facts.mtaStsPolicyRead && facts.mtaStsMode) {
    let out = "mode " + facts.mtaStsMode;
    const uncovered = facts.mtaStsUncovered || [];
    if (uncovered.length) {
      const hosts = facts.mxHosts || [];
      out += "; " + uncovered.length + " of the " + hosts.length +
        " exchangers not covered";
    }
    return out;
  }
  if (facts.mtaStsPolicyRead) {
    return "announced; the policy names no mode";
  }
  if (facts.mtaStsPolicyReason) {
    return "announced; the policy was not read: " + facts.mtaStsPolicyReason;
  }
  return "announced; the policy was not read";
}

// ── Submission ──────────────────────────────────────────────────────────

// domainOnly reduces a mail address to its domain, at the last "@".
//
// The part before it is a person, and no check has any use for it. Dropped
// here, in the browser, so it never reaches the service at all — the service
// drops it too, and a promise kept in two places survives either being changed.
function domainOnly(target) {
  const at = target.lastIndexOf("@");
  return at < 0 ? target : target.slice(at + 1);
}

async function check(target, spec) {
  spec = spec || CHECK;
  target = domainOnly(target);
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

  // A session that ended while the page was open: the gate says so, and the
  // page goes to sign in rather than reporting a check that never ran.
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Sign in to use this installation.");
  }

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
  if (!tally || DEMO_SITE) return;

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

/*
  Proof of control, on an installation that requires it.

  Asked before anything runs, so a name nobody proved anything about gets the
  record to publish rather than three refusals. The dialog stays until the
  record is seen or the person gives up, and the checks run the moment it is
  seen. Nothing here decides anything: the service asks the same question
  again on every scan, and this only saves a round of refusals.
*/
const proofDialog = document.getElementById("proof-dialog");
const VERIFY = { endpoint: "/api/v1/verify" };

function fillProof(records) {
  const level = document.getElementById("proof-level");
  clear(level);
  records.forEach((r, i) => {
    const option = el("option", null, r.domain);
    option.value = String(i);
    level.appendChild(option);
  });
  const pick = () => {
    const r = records[Number(level.value)] || records[0];
    document.getElementById("proof-name").textContent = r.name;
    document.getElementById("proof-value").textContent = r.value;
  };
  level.onchange = pick;
  // The broadest domain by default: one record then covers every name an
  // operator is likely to check. The list is most specific first.
  level.value = String(records.length - 1);
  pick();
}

// waitForProof resolves true once the record is seen, false if abandoned.
function waitForProof(target, first) {
  const status = document.getElementById("proof-status");
  const again = document.getElementById("proof-check");
  const cancel = document.getElementById("proof-cancel");

  fillProof(first.records || []);
  status.textContent = "";
  proofDialog.showModal();

  return new Promise(resolve => {
    const finish = ok => {
      again.onclick = null;
      cancel.onclick = null;
      proofDialog.oncancel = null;
      if (proofDialog.open) proofDialog.close();
      resolve(ok);
    };

    cancel.onclick = () => finish(false);
    proofDialog.oncancel = () => finish(false);

    again.onclick = async () => {
      again.disabled = true;
      status.textContent = "Looking for the record…";
      try {
        const answer = await check(target, VERIFY);
        if (answer.verified) {
          status.textContent = "Found. Running the checks.";
          finish(true);
          return;
        }
        status.textContent = "Not there yet. DNS can take a few minutes; check again shortly.";
      } catch (err) {
        status.textContent = err.status === 429
          ? "Asked too often. Wait a few seconds and check again."
          : (err.message || "The record could not be looked up.");
      } finally {
        again.disabled = false;
      }
    };
  });
}

/*
  Copying a proof record, and nothing else.

  The one place this script writes to the clipboard. A report is never put
  there: it names a host and what was found on it, and the clipboard is shared
  with every process on the machine and sometimes synced off it. A proof record
  is the opposite case. It exists to be pasted into a DNS provider's form, it
  proves nothing until it is published in that domain's zone, and the person
  pressing the button is about to paste it. Where the browser refuses the
  write, the text is selected instead, so one keystroke still copies it.
*/
async function copyRecord(button) {
  const source = document.getElementById(button.dataset.copy);
  if (!source) return;
  const text = source.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
  } catch {
    const range = document.createRange();
    range.selectNodeContents(source);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    button.textContent = "Selected";
  }
  setTimeout(() => { button.textContent = "Copy"; }, 1500);
}

for (const holder of [proofDialog, document.getElementById("domain-record")]) {
  if (!holder) continue;
  holder.addEventListener("click", event => {
    const button = event.target.closest("[data-copy]");
    if (button) copyRecord(button);
  });
}

/*
  Domains: the record for one domain, asked for before a check needs it.

  The same question the console asks when a check meets a new domain, through
  the same endpoint, shown on the page instead of in a dialog.
*/
const domainForm = document.getElementById("domain-form");
const domainRecord = document.getElementById("domain-record");

function showDomainRecord(answer) {
  const state = document.getElementById("domain-state");
  const level = document.getElementById("domain-level");
  const records = answer.records || [];

  state.textContent = answer.verified
    ? "Proven. Every check may run against this domain."
    : "Not proven yet. Publish this record, then check again.";
  state.className = "domain-state " + (answer.verified ? "mark-strong" : "mark-weak");

  clear(level);
  records.forEach((r, i) => {
    const option = el("option", null, r.domain);
    option.value = String(i);
    level.appendChild(option);
  });
  const pick = () => {
    const r = records[Number(level.value)] || records[0];
    if (!r) return;
    document.getElementById("domain-name").textContent = r.name;
    document.getElementById("domain-value").textContent = r.value;
  };
  level.onchange = pick;
  // The broadest domain by default, as the console's dialog does.
  level.value = String(Math.max(records.length - 1, 0));
  pick();
  domainRecord.hidden = false;
}

if (domainForm && domainRecord) {
  const target = document.getElementById("domain-target");
  const submit = document.getElementById("domain-submit");
  const again = document.getElementById("domain-again");

  const ask = async (button) => {
    const name = target.value.trim();
    const state = document.getElementById("domain-state");
    if (!name) {
      target.focus();
      return;
    }
    button.disabled = true;
    try {
      showDomainRecord(await check(name, VERIFY));
    } catch (err) {
      domainRecord.hidden = false;
      state.className = "domain-state mark-weak";
      state.textContent = err.status === 429
        ? "Asked too often. Wait a few seconds and try again."
        : (err.message || "The record could not be looked up.");
    } finally {
      button.disabled = false;
    }
  };

  domainForm.addEventListener("submit", event => {
    event.preventDefault();
    ask(submit);
  });
  again.addEventListener("click", () => ask(again));
}

// proven says whether the checks may run, asking for proof first where it is
// required. A failure to ask is shown in the results and ends the run.
async function proven(target) {
  if (!consoleForm || consoleForm.dataset.proof !== "required" || !proofDialog) return true;

  let answer;
  try {
    answer = await check(target, VERIFY);
  } catch (err) {
    consoleResults.appendChild(failure(err.message || "Whether this name is proven could not be checked."));
    return false;
  }
  if (!answer.required || answer.verified) return true;
  return waitForProof(target, answer);
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
      if (!(await proven(target))) return;

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

// ── The Porch page ──────────────────────────────────────────────────────

/*
  Every check on one name, each in a tab of its own.

  A tab per check rather than one long page, because the three answer
  different questions over different evidence and a reader usually wants one
  of them. Each tab carries its own state — running, a verdict, not graded, not
  run — so a TLS result is never read as saying anything about mail, and a
  check that failed says so without hiding the two that did not.

  The report inside a tab is the one every other page draws, built by the
  same functions from the same JSON (R16). Only the arrangement is new.
*/
const porchForm = document.getElementById("porch-form");
const porchTarget = document.getElementById("porch-target");
const porchButton = document.getElementById("porch-submit");
const porchResults = document.getElementById("porch-results");

function porchTabs(target, chosen) {
  clear(porchResults);
  porchResults.hidden = false;

  const head = el("div", "porch-report-head");
  head.appendChild(el("p", "eyebrow", "Live report"));
  head.appendChild(el("h2", "porch-report-title", target));
  porchResults.appendChild(head);

  const tabs = el("div", "tabs");
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Checks");
  porchResults.appendChild(tabs);

  // Every check has a tab, run or not. One chosen check drew one tab across
  // the whole width, which read as a banner rather than a choice; the others
  // are drawn switched off, so the row keeps its shape and says what was
  // left out. A switched-off tab has no panel and is not in the arrow-key
  // rotation, because there is nothing behind it.
  const entries = [];
  for (const name of CHECK_ORDER) {
    const spec = CHECKS[name];
    const on = chosen.includes(name);

    const tab = el("button", on ? "tab" : "tab tab-off");
    tab.type = "button";
    tab.id = "tab-" + name;
    tab.setAttribute("role", "tab");
    tab.appendChild(el("span", "tab-name", spec.label));
    const state = el("span", "tab-state", on ? "running" : "not selected");
    tab.appendChild(state);
    tab.appendChild(el("span", "tab-says", spec.says));
    tabs.appendChild(tab);

    if (!on) {
      tab.disabled = true;
      tab.setAttribute("aria-disabled", "true");
      tab.setAttribute("aria-selected", "false");
      tab.tabIndex = -1;
      continue;
    }
    tab.setAttribute("aria-controls", "panel-" + name);

    const panel = el("div", "tab-panel");
    panel.id = "panel-" + name;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", tab.id);
    panel.appendChild(el("p", "working", spec.working));
    porchResults.appendChild(panel);

    entries.push({ spec, tab, state, panel });
  }

  const select = index => {
    entries.forEach((entry, i) => {
      const on = i === index;
      entry.tab.setAttribute("aria-selected", String(on));
      entry.tab.tabIndex = on ? 0 : -1;
      entry.panel.hidden = !on;
    });
  };

  entries.forEach((entry, i) => entry.tab.addEventListener("click", () => select(i)));

  // The arrow keys move between tabs, as a tab list is expected to.
  tabs.addEventListener("keydown", event => {
    const at = entries.findIndex(entry => entry.tab === document.activeElement);
    if (at < 0) return;
    let next = at;
    if (event.key === "ArrowRight") next = (at + 1) % entries.length;
    else if (event.key === "ArrowLeft") next = (at - 1 + entries.length) % entries.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = entries.length - 1;
    else return;
    event.preventDefault();
    select(next);
    entries[next].tab.focus();
  });

  select(0);
  return entries;
}

async function runPorchEntry(entry, target) {
  try {
    const data = await check(target, entry.spec);
    clear(entry.panel);
    entry.panel.appendChild(entry.spec.build(data));

    const verdict = verdictOf(data);
    entry.state.textContent = data.verdict ? verdict : "not graded";
    entry.state.className = "tab-state " + verdictClass("stamp", verdict);
  } catch (err) {
    clear(entry.panel);
    const hint = err.status === 429
      ? "Wait a moment before trying again. Each host has its own budget, whoever asks."
      : err.status === 503
        ? "Several checks are running. Try again shortly."
        : null;
    entry.panel.appendChild(failure(err.message || "The check did not complete.", hint));
    entry.state.textContent = "not run";
    entry.state.className = "tab-state stamp-ungraded";
  }
}

if (porchForm) {
  porchForm.addEventListener("submit", async event => {
    event.preventDefault();

    const target = porchTarget.value.trim();
    const chosen = selectedChecks();
    if (!target || chosen.length === 0) {
      clear(porchResults);
      porchResults.hidden = false;
      porchResults.appendChild(failure(target ? "Choose at least one check." : "Choose a domain to check."));
      return;
    }

    porchButton.disabled = true;
    const label = porchButton.textContent;
    porchButton.textContent = "Checking";

    try {
      const entries = porchTabs(target, chosen);
      const still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      porchResults.scrollIntoView({ behavior: still ? "auto" : "smooth", block: "start" });

      // One at a time, as the console runs them: each check spends from the
      // host's budget, and three at once is the shape the budget discourages.
      for (const entry of entries) {
        await runPorchEntry(entry, target);
      }
    } finally {
      porchButton.disabled = false;
      porchButton.textContent = label;
    }
  });
}
