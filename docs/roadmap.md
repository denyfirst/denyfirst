# Where this is going

Decisions that are made, work that is next, and defects that are known. Kept
here rather than in anybody's notes, for the reason `docs/releasing.md` opens
with: a thing that lives in a chat window and in nobody's repository is in the
wrong place.

---

## Decided

**The tool is what you run. The site is a demonstration of it.**

Until 2026-09-03 anybody could point denyfirst.dev at any host on the internet
and this project's server opened the connections. That is the worst position
available: ours was the address in the scanned party's logs, and we had
deliberately made ourselves unable to say who had asked, because recording
that is the one thing this project undertakes not to do. There were two ways
out — start keeping records, which is not available, or stop connecting to
third parties. This is the second.

**The demonstration is complete about what it scans, and honest about what it
does not offer.** A report shown on the site shows everything that report
established, including whatever is wrong with our own host. What the site
limits is *which hosts* and *which checks* it will run, and it says so plainly
rather than hiding a finding behind an invitation to self-host. A report with
parts removed would be an advertisement, and the whole credibility of this
project rests on it not being one.

**No accounts, no records, on the deployment this project runs.** Anything
that needs an account is a feature of the tool other people run, not of the
service we do.

---

## Next, in order

### 1. The web check's service surface

`POST /api/v1/web/scan`, then `/web` and `/web/method`, then a front page at
`/` that runs both checks against one name and reports one worst-case verdict
with an explicit list of what neither established. `/` stops being a redirect
the day there is something to put there.

The demonstration guard is already in `webscan.Scanner.Scan`, so the endpoint
inherits it rather than having to remember it.

**The counters need a decision before the endpoint lands.** `Snapshot` carries
one verdict breakdown, and a `strong` mixing two rule sets means nothing. The
per-check figures have to be separated without breaking a published shape.

### 2. Scope: prove control of a domain before scanning it

**[`docs/scope.md`](scope.md) is the design**, settled: what a verified domain
does and does not authorise, why the two challenge methods grant different
things, what verification is not a reason to retire, and which of the public
deployment's restrictions belong to the deployment rather than to the check.
Read it before changing any of this. What follows is the summary.

A deployment should be able to require that a domain has been verified before
it will scan it — DNS TXT at `_denyfirst-challenge.<domain>`, or a file at
`/.well-known/denyfirst-challenge` for teams without DNS access.

This is a property of the tool, not a service anybody runs for anybody else.
It costs this project nothing in records, because this project is not in the
path.

What it buys is the thing that currently stops an organisation from putting a
self-hosted `denyfirstd` on its own network: without it, an internal
deployment where anyone can type a hostname is the arrangement this project
dismantled, rebuilt inside somebody's intranet. With it, an installation can
only reach estates it has proven control of — which also survives a careless
colleague, a compromised CI job, and an SSRF into the scanner.

Defaults differ because the threat models differ, and this is the part to get
right:

| | default | why |
|---|---|---|
| `denyfirst-scan`, in a terminal | off | whoever runs it already has the machine; nobody else can reach it |
| `denyfirstd`, a service | **on** | anything anyone can reach must not scan arbitrary hosts |

Architecturally it is a sibling of `internal/demo`: the same boundary, asked
in the same place, from a different source of authority — one compiled in, one
established at run time.

### 3. Mail

SPF with its ten-lookup and void-lookup limits, DMARC and alignment, MTA-STS,
TLS-RPT, DANE on the MX hosts. DNS only: nothing is connected to on the
target's mail path, which is the strongest privacy story any check here can
have. It comes after scope because proving control of a domain is the natural
condition for looking at its mail policy anyway.

### Later

Certificate revocation fetched live (command line only — a certificate
authority learns which certificate is being examined, and that is the
operator's decision about their own certificate, not ours to make for them).
Several trust stores. Transparency receipts verified offline against an
embedded log list. Every address a name resolves to, capped. Cookies in the
web check, which needs `Path` and `Domain` on `webprobe.Cookie` so `__Host-`
can be checked in full rather than in part. A hand-written ClientHello, for
SSLv3, export and NULL suites and per-suite TLS 1.3 enumeration.

---

## Known defects

**`certinfo` verifies against a different trust store from the one the service
checks.** `leaf.Verify` is called with a nil `Roots`, which means the system
pool, which on Windows and macOS means the platform verifier. Two of its tests
have failed on those platforms since they were written, because the fixture
points `SSL_CERT_FILE` and `SSL_CERT_DIR` at a private authority and only Go's
unix root loader reads those variables. Harmless while this ran on one Linux
server; not harmless now that self-hosting is the product. The store the
program checks at startup should be the store it verifies against, on every
platform, which means threading an explicit `*x509.CertPool` through.

**`denyfirst-scan -version` prints both rule sets but no reach line**, while
`denyfirstd` prints one. Every binary should say what it will connect to. A
deployment whose scope is established at run time rather than compiled in has
to appear on that line as well, or the property the deploy procedure reads
becomes false for the new mode.

**A self-hosted `denyfirstd` has no target boundary at all**, which is what
item 2 above is for. Until it lands, `docs/self-host.md` notes that loopback
is the default and does not say plainly that binding to a reachable interface
makes it an open scanner.

**`docs/releasing.md` tells you to run `gh pr checks --watch` immediately
after `gh pr create`.** No check has registered yet, the command exits saying
so, and the merge then fails for a reason that reads like a policy block.

---

## Not doing

**Exploitation, credential guessing, fuzzing somebody else's service, state
change, port sweeps, scanning at scale, or CVE guesses matched from a version
string.** None of these was ever a logging question, and none of them became
available when this project stopped being a public intermediary. The last is
where most scanners lose their readers' trust.

**Accounts or scan history on denyfirst.dev.** *I do not have the data to
begin with* is a stronger statement than any policy, and it is not a claim to
retire by accident. If it is ever retired it will be a separate, deliberate
decision with terms, a data-processing agreement and an abuse process behind
it.

**A subscription, for now.** If this becomes something organisations want, the
thing they pay for is continuous monitoring, inventory, evidence for auditors,
integrations and support — around a tool they run themselves. None of that
requires this project to hold anybody's scan history.
