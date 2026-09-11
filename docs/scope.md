# Who may scan what, and where that is decided

`docs/invariants.md` says why each guard is written the way it is.
`docs/roadmap.md` says what is coming. This says how the guards fit together
into one boundary, because the answer has changed once already and changing it
again by accident is the failure this document exists to prevent.

Everything here is public. It carries no personal preference, no account, no
session identifier, and nothing about who is working on it.

---

## The question

A scanner opens connections to somebody's server. Two facts decide everything
else about it:

- **Whose address is in the scanned party's logs.** Until 2026-09-03 it was
  ours, for scans nobody asked us about.
- **Whether we can say who asked.** We cannot, deliberately, and that is the
  one promise this project is built on.

Holding both at once is the worst position available — the visible party and
the unattributable one simultaneously — and N6 is the decision that ended it.
There were two ways out: start keeping records, which is not available because
the promise is the point, or stop connecting to third parties. The second was
taken.

That decision is not being revisited. What follows is how it extends to
deployments this project does not run.

---

## Three deployments, not two

The code has two builds. It has **three** deployments, and conflating the last
two is where a boundary would be lost.

| | who runs it | who chooses the target | what stops it |
|---|---|---|---|
| **the demonstration** — denyfirst.dev | this project | a stranger | a list compiled into the binary (N6) |
| **a self-hosted service** — `denyfirstd` | an organisation | anyone who can reach it | **nothing today** |
| **the command line** — `denyfirst-scan` | one person | that person | nothing, by design |

The command line needs nothing. Whoever runs it already has the machine, the
scan leaves from their own address, and nobody else can reach it. A default
that restricted anything there would quietly limit somebody scanning their own
network, which is what the tool is for.

The demonstration is settled. The list is compiled in, the gate is the build
tag rather than the length of the list, and a binary says which hosts it will
connect to so that a deploy can read it rather than trust a filename.

**The middle row is the open one.** A `denyfirstd` built without the tag has no
restriction at all. It listens on loopback by default, which means an
accidental start is not immediately public — but a default is a mitigation, not
a boundary. An organisation that binds it to an interface has rebuilt, inside
its own network, the arrangement this project dismantled: anyone who can reach
the box can point it at anything, and now it is *their* address in the scanned
party's logs.

That is not a hypothetical for somebody else. It is the arrangement a careless
colleague reaches by accident, a compromised CI job reaches on purpose, and an
SSRF into the scanner reaches for free.

---

## The boundary for a self-hosted service

**A deployment scans only estates it has proven control of.**

Proof is a challenge the operator satisfies once per domain: a DNS `TXT`
record at `_denyfirst-challenge.<domain>`, or a file at
`/.well-known/denyfirst-challenge` for teams without DNS access.

Architecturally this is a sibling of `internal/demo`: the same boundary, asked
in the same place, from a different source of authority — one compiled in, one
established at run time. Five properties decide whether it works.

**Defaults differ because the threat models differ.**

| | default | why |
|---|---|---|
| `denyfirst-scan`, in a terminal | off | whoever runs it already has the machine |
| `denyfirstd`, a service | **on** | anything anyone can reach must not scan arbitrary hosts |

A protection that must be switched on is one that is eventually forgotten,
which is the same argument `AllowAnyPort` and `safedial` already make.

**It is asked where the scan is decided, not where the request arrives.**
`Scanner.Scan` and `webscan.Scanner.Scan`, beside `demo.Refusal`. A guard in
one entry point disappears the moment a second one is added, and adding entry
points is exactly what this project is now doing. Checking once at startup and
holding a flag would make it a configuration boundary, and N6 says what
happens to those: a flag can be omitted, a file can be edited, an environment
variable can be missing, and nothing looks wrong.

**It is re-read rather than remembered.** A DNS lookup is one round trip. A
verification that never expires is a standing authorisation that outlives the
relationship it came from: a domain changes hands, a supplier contract ends, a
subsidiary is sold, and a record removed at the registrar is a record this
scanner is still acting on. Re-reading also means revocation works by deleting
the record, which is the only revocation mechanism an operator will actually
find.

**The two methods do not prove the same thing, so they do not grant the same
thing.** A `TXT` record proves control of the zone. A file proves control of
one host's HTTP surface — which is narrower, and is exactly the thing being
scanned, so it is not weaker, only smaller. Therefore:

- DNS `TXT` authorises the zone.
- A `.well-known` file authorises **that hostname only** — never the zone,
  never another name, and never a check that does not read HTTP.

**A verified zone is not a list of hosts you control.** This is the part most
easily got wrong. Subdomains are delegated: `shop.example.com` is a `CNAME` to
a shop platform, `mail.example.com` to a mail provider, `docs.example.com` to
whoever hosts documentation. Scanning them reaches somebody else's servers
under an authorisation the somebody else never gave, which is N6's problem
rebuilt inside a verified deployment. The apex is not exempt: an `A` record
often points at a CDN.

There is no clean automatic answer to this, and inventing one would be a
threshold nobody can argue with — the failure R21 is written about. What the
tool can honestly do is **say what it is about to reach**: name the delegation
it is scanning through, so the operator makes the call rather than the scanner
making it for them.

---

## Two scopes, one methodology

This is the shape of the whole product, and it is written here because getting
the words wrong is how it would be lost.

```
                    DENYFIRST
                       │
              ┌────────┴────────┐
              │                 │
          UNVERIFIED         VERIFIED
              │                 │
        public scope        owned scope
              │                 │
        read / observe     read / observe
              │                 │
         same safe           same safe
        methodology         methodology
              │                 │
         no exploit          no exploit
         no fuzzing          no fuzzing
         no guessing         no guessing
              │                 │
              └────────┬────────┘
                       │
                MINIMAL RETENTION
```

**Verification changes where this tool may look. It never changes how it
looks.** The two branches separate on scope and rejoin on method, and the
rejoining is the part that matters: a verified deployment is not a different
tool with the safety catch off. It is the same instrument, pointed at more of
what belongs to the person holding it.

The temptation is to describe the right-hand branch as *full*, *deep* or
*active*, and each of those words quietly authorises something this project has
already refused. So the axis is named for what actually differs — **whose
network it is** — and never for how hard the tool pushes.

| | unverified | verified |
|---|---|---|
| which hosts | what the deployment was built to reach | the estate proven control of |
| private, loopback, reserved | refused | an operator's own decision, off by default |
| ports | the implicit-TLS list | an operator's own decision, off by default |
| how a host is examined | **identical** | **identical** |
| what is retained | **identical** | **identical** |

Everything above the double line is about *whose network it is*. Everything
below it is about *what kind of thing this is*, and no deployment model touches
it. `docs/invariants.md` has the guards; the roadmap's "Not doing" section has
the argument for the bottom three lines of the diagram, and it is worth reading
in full, because the strongest reason there is not about the scanned party at
all:

> A tool that sends deliberately broken input is a weapon in whoever's hands it
> ends up in. This one is meant to be installed by a company to check itself,
> and the property that makes that safe is that the worst a careless colleague
> can do with it is read a page.

Proving control of `example.com` proves that `example.com` is yours. It does
not make it safe to hand every junior on the team a tool that can take a
production service down, and a deployment boundary is not an argument for
building one.

**Completeness comes from more passive checks, not from active ones.** An
organisation that installs this to find its own gaps is owed all of them, and
the way there is more that can be read — mail policy, which is DNS only; every
address a name resolves to; the operator's own ports; several trust stores.
What is given up by refusing the active class is roughly one finding, because
almost everything reachable by malformed input is either reachable by a fuller
ordinary handshake or has a precondition that is plainly visible. Where it is
given up, the report says so rather than staying quiet.

---

## What verification does not do

**It changes who is responsible. It does not change what the tool does.**

A verified deployment can still be reached by an SSRF, driven by a compromised
CI job, or misconfigured. So verification is not a reason to retire:

- `safedial`'s refusal of private, loopback, link-local and reserved
  destinations by default;
- the port allow list;
- the per-client rate limit, the concurrency cap, the per-target budget;
- the cross-site check and the read allowance;
- anything in N7 — one `GET` of `/`, no path ever constructed, the body never
  read, an allow list of headers, and nowhere to put a cookie's value.

If verification ever becomes the argument for dropping one of these, the
argument is wrong and this paragraph is why.

**It does not make a bare address scannable.** Verification is name-based:
there is no zone to put a record in for `10.0.0.5`. A name that resolves to a
private address can be verified and then scanned — that composes. An IP typed
as a target cannot, and stays where it is today: available on the command
line, which runs on the operator's own machine, and absent from the service.

**It does not travel down a redirect.** A verified zone authorises the hosts in
it, and a `Location` header names whatever the server that answered chose to
name. So the scope is asked again about that host, before the hop is dialled,
and a chain that leaves the zone stops there with the reason recorded (N10).
Anything else would mean one header on a site an organisation does own could
walk its scanner out of its own estate — into a third party's logs, from the
organisation's address, on the strength of a proof that was about somewhere
else.

The same holds in the other direction and is worth saying, because it is the
part an operator notices: a record at `example.com` covers `www.example.com`,
so the ordinary redirect is followed and the report is whole.

**It settles whose certificate is being examined, which decides one
disclosure.** Reading a revocation list tells the authority that somebody
downloaded a list — not which certificate was being looked at, since one list
covers thousands and authorities serve them from content delivery networks to
the whole internet. That is a smaller disclosure than the one this project
refused when it refused OCSP, where the serial is named in the question.

It is still a request, and the demonstration deployment promises it makes none,
so the call is compiled out of that build. Everywhere else it runs with no
switch: on a deployment that requires proof of control the certificate belongs
to whoever asked, and a person has nothing to hide from themselves. A switch
they had to find first would be a gap in a report dressed as a choice — which
is the shape of the question to ask about every future check that discloses
something. *Whose is it, and what exactly does the other party learn?*

**The same question, asked of the certificate logs, gets a different answer —
and that is the point of asking it.** Searching for the certificates issued for
a name sends the name to a monitor. That is the OCSP shape, not the revocation
list shape, so it is offered differently: never on the demonstration, with no
switch on a deployment that required proof of control, and behind `-check-logs`
on the command line, where the name may be somebody else's.

What makes it acceptable at all is that certificate transparency is public by
design — the certificates for a name are already published to anyone who looks,
so only the looking is disclosed. That reason survives a change of provider. A
reason about the provider being a security company would not, and is not the
one relied on here (N12).

**It is visible.** `_denyfirst-challenge.example.com` sits in public DNS and
says the organisation uses this tool. That is the ordinary cost of every
challenge-based scheme and it is not worth hiding; it is worth naming, here
and on the privacy page, rather than leaving it to be found.

---

## What the public deployment's strictness was, and what it was for

Several rules are strict because a stranger was pointing our server at a third
party. Where that is no longer the situation, the rule can be re-scoped — but
each one is a separate decision with a separate reason, not a general
loosening, and each belongs to the deployment rather than to the check.

**Re-scopable for a verified self-hosted deployment**, in descending order of
how clearly:

| | today | re-scoped | condition |
|---|---|---|---|
| which hosts | a compiled-in list | the verified scope | the whole point |
| private and reserved destinations | refused | reachable | verified names only, off by default |
| the port allow list | eight implicit-TLS ports | any | verified names only, off by default |
| per-target budget | one budget per host, whoever asks | the operator's setting | the oracle it closes (A9) does not exist inside one estate, and the load it caps is then the operator's own |
| scan history and counters | one number per scan, nothing else | the operator's business | it is their data about their estate, and nothing here is a promise made on their behalf |

**Not re-scopable, on any deployment**, because these are properties of being
a measurement instrument rather than concessions to running in public:

- Everything in N7. A tool that constructs a path is a different tool.
- I3 and I6 — a message says what the rule is, never repeats the input, never
  describes the machine.
- The R-series — say what was measured and not what it implies; a verdict
  cites a document; where no document sets a threshold, report rather than
  grade; nothing measured is not the same as passing.
- The "Not doing" list in the roadmap: exploitation, credential guessing,
  fuzzing somebody else's service, state change, port sweeps, scanning at
  scale, and CVE guesses matched from a version string.

The first list is about *whose network it is*. The second is about *what kind
of thing this is*, and no deployment model changes that.

---

## Known gaps, as of 2026-09-10

Each is either scheduled or has a defect entry. None is silent.

**A self-hosted service has no boundary at all.** The subject of this
document; roadmap item 2. Until it lands, `docs/self-host.md` says that
loopback is the default, and should say plainly that binding `denyfirstd` to a
reachable interface makes it an open scanner.

**A binary says which hosts it will connect to, and a verified deployment has
no answer yet.** `denyfirstd -version` composes its reach line from the
compiled-in list. A deployment whose scope is established at run time has to
say so on that line too, or the property N6 relies on for deploys becomes
false for the new mode. `denyfirst-scan -version` prints no reach line at all,
which is its own roadmap defect.

**Reading a response body is listed above as never re-scopable, and a check
worth having needs it.** Mixed content, a missing subresource integrity
attribute, and a form that posts to somebody else's origin are ordinary gaps an
organisation has and cannot see from headers alone. All three are read-only, a
browser reads the same bytes, and on a verified deployment the page belongs to
whoever asked — so the reason for the rule is weaker here than the list above
makes it sound.

The reason that survives is not bandwidth. It is that a body holds things a
report must never carry: a leaked key in a comment, a token in a script, a name
in a template. A report is a thing people paste into issue trackers.

So the shape this would have to take, if it is ever built, and it is written
down now because deciding it later under pressure is how it goes wrong:

- **Only where control has been proven.** The demonstration verifies nothing —
  it reaches a compiled-in list — so it would keep reading no body at all, and
  the promise on `/web/method` stays literally true for the reader who found
  that address in a log. Two deployments would then be telling two different
  true things, and the page has to say which one it is rather than shipping one
  sentence for both.
- **Nothing kept but derived facts.** The struct that reaches a report has
  nowhere to put a body, in the way `webprobe.Cookie` has nowhere to put a
  value. What survives is "a subresource was loaded over plaintext", not the
  markup that said so.
- **Capped and streamed**, so a large page costs a bounded read.
- **Still no path is constructed.** This reads the body of `/` and of what a
  `Location` header named. It does not follow a link, fetch a script, or ask
  for anything the response mentioned.

**Not decided, and not started.** It changes a published promise, so it is a
release note and a deliberate decision, not a side effect of adding a check.

