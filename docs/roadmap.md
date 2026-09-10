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

**The web check has its service surface**, since 2026-09-10: `POST
/api/v1/web/scan`, `/web`, and `/web/method`. What is left is a front page at
`/` that runs both checks against one name and reports one worst-case verdict
with an explicit list of what neither established. `/` stops being a redirect
the day there is something to put there.

The endpoint inherited the demonstration guard and the exclusion list rather
than repeating them, because both are asked in `webscan.Scanner.Scan`. It
walks the same chain of guards the TLS endpoint does — there is one chain,
described per check rather than copied per endpoint, and N6 says why.

The method page came before the page a visitor scans from, because the web
probe has been naming that address in other people's access logs since the
endpoint landed and it answered 404 (N7). It is written for the log reader
first.

**The counters were settled first.** Each check has its own block naming its
own rule set; the fields at the top of a `Snapshot` are still the TLS check's,
spelled the same and counting the same thing, and the `tls` block repeats
them. Nothing published moved, so a reader of `/api/v1/stats` and a rollback
to an older binary both keep figures that mean what they meant. R22 has the
reasoning.

**The privacy page describes one figure per scan** and needs a sentence now
that a second check is counted. Nothing new is recorded — no hostname, no
address, no time — but the page says what is kept and has to keep saying it
accurately. It belongs with the `/web` page work rather than ahead of it.

### 2. Scope: prove control of a domain before scanning it

**The boundary is built and is opt-in**, since 2026-09-10: `internal/verify`,
asked in both scanners beside the demonstration list, and
`-verification-secret-file` on the service. N9 has the reasoning.

It was asked in both scanners and configured on one. `httpapi.New` built the
web check from nothing, so a service that set a scope refused an unproven host
on `/api/v1/tls/scan` and measured it on `/api/v1/web/scan` — every guard in
place, every unit test passing, and no boundary on half the surface. The
constructor now hands the boundary to every check it builds, `UseWebScanner`
cannot drop it, and the test drives the `POST` routes read out of the source
rather than a list somebody has to remember to extend.

What is left is the default. `docs/scope.md` says it belongs **on** for a
service, and turning it on stops every deployment that has not published a
record yet — a change to make deliberately, with a release note, rather than
as a side effect of an upgrade. Until then a service with no secret configured
scans whatever it is asked to, and says so at startup.

The `.well-known` half is also still to come. It authorises one hostname
rather than a zone, and the difference is in `docs/scope.md`.

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
embedded log list. Every address a name resolves to, capped. A hand-written ClientHello, for
SSLv3, export and NULL suites and per-suite TLS 1.3 enumeration.

---

## Known defects

**`denyfirst-scan -version` prints both rule sets but no reach line**, while
`denyfirstd` prints one. Every binary should say what it will connect to. A
deployment whose scope is established at run time rather than compiled in has
to appear on that line as well, or the property the deploy procedure reads
becomes false for the new mode.

**A self-hosted `denyfirstd` requires no proof by default.** The boundary
exists and is opt-in; the default is the remaining half of item 2 above. Until
it changes, `docs/self-host.md` notes that loopback is the default and does
not say plainly that binding to a reachable interface without
`-verification-secret-file` makes it an open scanner.

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

**Nothing malformed is ever sent**, and the reason has changed, so it is
written down rather than left to be inferred from the line above.

The old reason was that the server belongs to somebody else. Once a deployment
scans only estates it has proven control of, that reason is weak: it is your
own server, and looking at it harder is your decision. Three reasons survive
and none of them is about the scanned party.

A tool that sends deliberately broken input is a weapon in whoever's hands it
ends up in. This one is meant to be installed by a company to check itself,
and the property that makes that safe is that the worst a careless colleague
can do with it is read a page. That property is worth more than any finding it
costs.

Several of these probes can destabilise the service they are aimed at, and a
check that can take down the thing it is checking is not a check anybody runs
on a Tuesday afternoon.

And the class has a poor accuracy record. A false "vulnerable to ROBOT" sends
a team after a week of work that was never needed; a false "clean" is worse.
This project's whole argument is that its answers can be relied on, and a
family of checks that has historically been wrong in both directions is a bad
trade for a report that is otherwise checkable line by line.

**What is given up is smaller than it looks, and where it is given up the
report says so.** Almost everything reachable by malformed input is either
reachable by a fuller ordinary handshake — a wider ClientHello, the offered
suites, the parameters a server volunteers — or has a precondition that is
plainly visible. A Bleichenbacher oracle can only exist behind a static RSA
key exchange, and that is graded `insecure` on sight; the finding now says
what confirming the oracle would take, that this tool does not do it, and that
the remedy is the same instruction either way. A reader loses the confirmation
and keeps the action.

**Accounts or scan history on denyfirst.dev.** *I do not have the data to
begin with* is a stronger statement than any policy, and it is not a claim to
retire by accident. If it is ever retired it will be a separate, deliberate
decision with terms, a data-processing agreement and an abuse process behind
it.

**A subscription, for now.** If this becomes something organisations want, the
thing they pay for is continuous monitoring, inventory, evidence for auditors,
integrations and support — around a tool they run themselves. None of that
requires this project to hold anybody's scan history.
