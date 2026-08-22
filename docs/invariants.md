# Security invariants

Every rule below states something that must be true of this project, where it
is enforced, and which test would fail if it stopped being true.

The list exists because of a pattern that repeated four times while this code
was being written. A guard was placed where the request arrived rather than
where the dangerous action happened, and each time the gap was found by
someone asking rather than by anything failing. A protection that depends on
whoever is reviewing remembering to look for it is not a protection.

Two rules follow from that, and they apply to every change:

**Guard the action, not the entrance.** A check in an HTTP handler protects
that handler. A check in the package that opens the connection protects every
caller, including the ones not written yet. When both are reasonable, put it in
the inner one and let the outer one improve the message.

**Every guard gets a test that tries to defeat it.** Not a test that the happy
path works: a test that the guard refuses. A guard without such a test is an
intention.

---

## Network

### N1 — Outbound connections refuse non-public addresses

Private, loopback, link-local, multicast, and reserved ranges are refused
before any connection is made. IPv4-mapped IPv6 forms are unmapped first, so
`::ffff:169.254.169.254` is treated as the link-local address it is.

An IPv6 address can also carry an IPv4 address without being mapped, and no
predicate in the standard library looks inside one. `::127.0.0.1` is the
deprecated IPv4-compatible form from RFC 4291: `IsLoopback` returns false for
it, `Unmap` leaves it alone, and before this was written it reached the
dialler as an ordinary global address. Teredo does the same at a different
offset, 6to4 and NAT64 at two more, and RFC 2765's IPv4-translated form
`::ffff:0:a.b.c.d` at a fifth — sixteen bits longer than the mapped form and
therefore a different prefix, which is how it stayed out of the list while its
neighbour was in it. Each family needs a prefix of its own, and `2001::/23`
covers several at once because IANA reserved that block for exactly this kind
of assignment.

That last family is not routed by a stock Linux stack, so nothing broke while
it was missing. It is listed because a deny list is worth exactly its
completeness, and "not reachable on the kernel we happen to run" is a property
of the kernel rather than of this code.

The hostname is resolved once and the resolved literal is dialled, so a name
that answers differently on a second lookup cannot redirect the connection
after it was checked.

This is a deny list, which is the shape this document argues against. The
reason is stated rather than hidden: the standard library has no predicate for
"inside a range IANA has delegated to somebody", so an allow list would mean
carrying the delegation registry and keeping it current. A range added to the
special-purpose registry after the list was written is not covered until
somebody adds it.

*Enforced in:* `internal/safedial`, by default in `safedial.Dialer`
*Reached through:* `tlsprobe.Prober.dial`, which selects safedial when
`Dial` is nil
*Guarded by:* `TestCheckAddrBlocks`, `TestEmbeddedIPv4FormsAreBlocked`,
`TestSpecialPurposeBlockDoesNotReachDelegatedSpace`,
`TestDefaultDialerRefusesPrivateTargets`,
`TestZeroScannerRefusesPrivateTargets`, `TestPrivateTargetsAreRefused`

### N2 — The HTTP service cannot be configured to reach private addresses

The command line has `-allow-private`, because a local operator scanning their
own network is not the abuse N1 guards against. The service has no equivalent,
and adding one would make it an open proxy into whatever network it runs in.

*Enforced by:* the absence of any option in `internal/httpapi`
*Guarded by:* `TestPrivateTargetsAreRefused`

### N3 — Only implicit-TLS ports are dialled

Dialling arbitrary ports on arbitrary hosts makes this a port scanner
operating from our address, and the scanned network's logs will name us.

*Enforced in:* `internal/scan`, in `Scanner.Scan`, unless `AllowAnyPort`
*Lifted by:* the command line only
*Guarded by:* `TestScannerEnforcesPortsByDefault`, `TestCheckPort`,
`TestAllowedPortsAreImplicitTLS`

### N4 — Every network operation is bounded

A per-attempt timeout multiplies by the number of addresses tried, so there is
also a total budget, and a cap on how many resolved addresses are attempted. A
caller's deadline is never extended.

*Enforced in:* `internal/safedial` (`Timeout`, `TotalTimeout`, `MaxAddrs`),
`internal/tlsprobe` (`HandshakeTimeout`, `TotalTimeout`),
`internal/httpapi` (`RequestTimeout`)
*Guarded by:* `TestCallerDeadlineWins`, `TestTotalTimeoutBoundsTheOperation`

---

## Input

Every bug found in this project so far has been here. Six of them: an empty
port, brackets left on a hostname, several colons, a signed port number, a
name with no dot, and a path discarded in silence. None was reachable as an
attack, and all six were the same shape — input that parsed into something
other than what the person meant, so that the value checked was not the value
dialled.

Treat a change to `SplitTarget` as a change to a security boundary, whatever
it looks like. Add a fuzz seed for anything new it accepts or refuses.

### I1 — One implementation of target parsing

The command line receives typos; the service receives whatever a stranger
sends. Two implementations would diverge, and the stricter requirement must
set the rule for both.

*Enforced in:* `internal/scan.SplitTarget`
*Guarded by:* `TestSplitTarget`, `TestSplitTargetRejectsMalformedInput`

### I2 — Interior control characters are refused

Surrounding whitespace is trimmed, because people paste it and nothing
survives the trim. What remains inside the string is different: a newline in a
hostname is where header injection starts, and a NUL byte is how a truncating
parser is made to read a name other than the one that was checked.

*Enforced in:* `internal/scan.SplitTarget`
*Guarded by:* `TestSplitTargetRejectsMalformedInput`

### I3 — Error messages describe the rule, never repeat the input

Anything a caller sent that comes back in a response is a reflection, and a
reflection becomes cross-site scripting the moment something renders it. This
applies to the port as well as the host: `net.SplitHostPort` does not require
a port to be numeric.

*Enforced in:* `internal/httpapi`, in every `writeError` call
*Guarded by:* `TestErrorsDoNotEchoInput`

### I4 — Request bodies are capped before parsing

*Enforced in:* `internal/httpapi`, `http.MaxBytesReader` ahead of the decoder
*Guarded by:* `TestBodySizeLimit`

### I5 — Unknown JSON fields are refused

A misspelled key fails loudly rather than being silently ignored.

*Enforced in:* `internal/httpapi`, `Decoder.DisallowUnknownFields`
*Guarded by:* `TestRejectsMalformedBodies`

### I6 — Error messages do not describe this machine

A published error names the shape of a failure and nothing else. Not the
resolver this service uses, not the address that was dialled, not a path on
disk.

I3 covers the input side: what a caller sent is never repeated back. This is
the output side, and it was open for longer because the leak arrives from a
library rather than from our own formatting. Go writes network errors for an
operator reading a terminal, so they name whatever helps there — and one of
those things is the resolver's address, which belongs to whoever runs the
machine.

The rule is that every branch of `classifyHandshakeError` returns a phrase
written in that function. There is no pass-through, and the default case is a
phrase rather than the error: an unrecognised failure is the one most likely
to carry an address, and the one nobody has reviewed.

*Enforced in:* `internal/tlsprobe.classifyHandshakeError`
*Guarded by:* `TestHandshakeErrorsCarryNoInfrastructure`,
`TestReportFromAFailedProbeNamesNoAddress`

### I7 — One host has one spelling

DNS is case-insensitive and a trailing dot names the same zone, so
`EXAMPLE.COM`, `example.com` and `example.com.` reach one server. Parsing
returns one of them.

This is the same rule the port already had — `checkPortSyntax` refuses `+443`
and `0443` so that one value has one spelling — and it was missing for the
thing that matters more. Something downstream compares hostnames for a living:
the per-target rate limit hashes the name to recognise a repeat, and a hash is
exact where DNS is not. Without folding, a caller spelled the name differently
on each request and was handed a fresh budget every time. That budget is the
only limit in this project that protects the party being scanned rather than
this service, and one scan is up to fifty handshakes at the other end.

Folding happens where parsing happens, so one form reaches the exclusion list,
the limiter, the client hello, and the target echoed back in the report. A
canonical form computed in one place and not another is how a check comes to
describe something other than what was dialled. The limiter folds again on its
own, which is the same argument N3 makes about where a guard belongs.

Two trailing dots is not a spelling but an empty label, and is refused rather
than folded.

*Enforced in:* `internal/scan.canonicalHost`, `internal/httpapi.foldHost`
*Guarded by:* `TestSplitTargetFoldsSpelling`, `TestSplitTargetFoldsAddresses`,
`TestHostWithATrailingEmptyLabelIsRefused`, `TestFoldingIsStable`,
`TestTargetLimiterIgnoresSpelling`,
`TestSpellingCannotBuyExtraScansOfOneHost`, `FuzzSplitTarget`

---

## Availability

### A1 — Rate limiting is per client and cannot be chosen by the client

`X-Forwarded-For` is ignored unless a proxy is declared, because otherwise
every client can mint a new limit key per request. Where a proxy is declared,
the entry is counted from the right: each proxy appends the address it
received the request from, so the leftmost entry is whatever the client typed.

IPv6 is keyed on the /64. A subscriber holds a whole prefix and can present a
new address per request, which would make a per-address limiter decorative.

*Enforced in:* `internal/httpapi`, `clientKey` and `limiter`
*Guarded by:* `TestRateLimitIsPerClient`, `TestIPv6IsLimitedPerPrefix`,
`TestForwardedHeaderIgnoredWithoutTrustedProxy`,
`TestForwardedHeaderIsIgnoredFromUndeclaredNetworks`,
`TestForwardedHeaderIsReadFromDeclaredNetworks`,
`TestForwardedForReadsTheProxyLineNotTheClients`

### A2 — The rate limiter's memory is bounded

An unbounded map turns a rate limiter into a memory exhaustion primitive,
because an attacker rotating source addresses adds an entry per request. Idle
buckets are swept, and past a cap new clients are refused rather than
admitted.

*Enforced in:* `internal/httpapi`, `limiter.maxKeys` and `limiter.sweepLocked`
*Guarded by:* `TestLimiterMemoryIsBounded`, `TestLimiterSweepsIdleClients`

### A3 — Concurrent scans are capped

A scan holds a socket for as long as the request timeout allows, and a slow
target holds it for all of it.

*Enforced in:* `internal/httpapi`, `semaphore`
*Guarded by:* `TestConcurrencyLimit`

### A4 — Every endpoint has a budget

The scan endpoint was limited from the first day; the two read-only endpoints
were not. That was an omission rather than a decision — `/api/v1/stats` clones
a map on every call, so a client asking a few thousand times a second turns a
health check into a way of spending this machine's processor.

The two allowances are separate. A monitor polling every few seconds is the
intended use of the read endpoints and must not consume a scan allowance; a
client that has spent its scan budget must not be able to refill it by asking
for statistics instead.

*Enforced in:* `internal/httpapi.Server.readLimited`
*Guarded by:* `TestReadEndpointsAreLimited`

### A5 — A full limiter does not become a lock

Every limiter here has a bounded map, because an unbounded one turns a rate
limit into a way of exhausting memory. The bound has its own failure mode: if
reaching it means refusing every client the service has not already seen, then
one client able to produce many keys can shut the door on everybody.

So a full map is swept first — it is usually stale rather than busy — and then
one entry is dropped to make room. Which entry does not matter much; losing a
bucket costs its owner a fresh allowance and nothing else. The map stays
bounded and the service stays open, which is the pair of properties that has
to hold together.

The same reasoning governs what may become a key. X-Forwarded-For is written
by the first client in the chain, so an entry that is not an address is not an
identity: the connection's own address stands instead. Otherwise a client
willing to send different nonsense on each request fills the map by itself.

The header is read as every line joined, not as the first one. A proxy may
extend the header the client sent or add a line of its own; both are
conforming, and several load balancers do the second. `Header.Get` returns
only the first line, so against such a proxy it returns what the client wrote
— a fresh key of the client's choosing on every request, which is this
invariant failing while looking like it holds.

*Enforced in:* `internal/httpapi.limiter.makeRoomLocked`,
`internal/httpapi.clientKey`
*Guarded by:* `TestFullLimiterStillAdmitsNewClients`,
`TestForgedForwardedForCannotMakeNewKeys`,
`TestForwardedForReadsTheProxyLineNotTheClients`

### A6 — A refusal is cheap, not free, so a refusal is limited too

Two checks used to run before the rate limiter: the cross-site check and the
content type check. The reason was sound — a page on another site must not be
able to spend the visitor's scan allowance on their behalf — and the
conclusion drawn from it was not. An early refusal still takes the counter
lock and still moves a figure this service publishes, so an unlimited refusal
path is both a way to spend this machine's processor and a way to write into
the only numbers an operator has to watch.

The allowance spent by a refusal is the read one, so the original reason still
holds: a cross-site request cannot touch the scan budget.

That last sentence was, until it was tested, only a sentence. Every test around
it passed with the two checks in either order, because in either order the
request is refused, with 403, counted as `cross_site`. What the order decides
is who pays for it — and behind the wrong order, a page on another site empties
a visitor's scan allowance in a handful of requests and leaves this service
refusing that visitor for reasons they cannot see.

*Enforced in:* `internal/httpapi.Server.handleScan`, the read limiter at the
top
*Guarded by:* `TestRefusalsBeforeTheScanAreLimited`,
`TestReadAndScanBudgetsAreSeparate`,
`TestPollingReadsDoesNotSpendTheScanAllowance`,
`TestACrossSiteRefusalDoesNotSpendTheVisitorsScanBudget`

### A7 — Every reason a request can be refused is counted, and a counted reason can occur

The first half was already true: `refuse` counts before it writes, so a
refusal cannot be added without being counted, and a code outside the list is
dropped rather than counted.

The second half was not, and it is the half that misleads. `blocked_destination`
was declared, documented as the signal that somebody is aiming this service at
the network it runs in, and permanently zero — safedial's refusal became a
note inside a successful report, so nothing ever reached the counter.
`timeout` was the same: a probe does not fail, it measures, so the error
branch that counted it could not run. A counter that cannot move is not a low
number. It is silence, and an operator reads silence as nothing happening.

One code remains unreachable by construction and is named in the test rather
than left to be discovered: `scan_failed`, because `scan.Scan` cannot fail
once the handler has validated the target. It is written as a counted refusal
anyway, since the signature permits an error and an uncounted one would be the
same hole in a different place.

*Enforced in:* `internal/httpapi.Server.refuse`,
`internal/tlsprobe.Report.BlockedDestination`
*Guarded by:* `TestEveryRefusalCodeCanBeProduced`,
`TestOnlyKnownRefusalCodesAreCounted`

### A8 — The per-target table regenerates faster than this service can spend it

Every bucket empty means every user refused, and that failure is worse than an
ordinary flood for being quiet: nothing is overloaded, no limit visibly fires,
the service simply says no to everybody.

Whether it is reachable is arithmetic, and the arithmetic was guessed before it
was measured. A scan of a name that does not resolve takes 16 to 19 ms on the
live service, so eight concurrent scans is about 470 a second. At twelve bits
the table regenerated 137 slots a second — so roughly sixteen hundred addresses
could hold the whole table dry while using under a third of this machine's
capacity, and nothing about the machine would look wrong. At sixteen bits it
regenerates 2185 a second, more than this service can spend at full tilt, so
the attempt now requires saturating the service; and a saturated service says
`too_busy`, which somebody can see.

Three numbers decide it and two live in other files, which is why the check is
a test rather than a comment: raising `MaxConcurrent`, or making a scan faster,
moves the same line.

*Enforced in:* `internal/httpapi.targetKeyBits`
*Guarded by:* `TestTargetTableOutrunsTheService`

### A9 — A shared limit does not answer questions about other people

A limit that refuses on the strength of somebody else's activity is a question
anybody outside can ask: scan a host, be refused, and you have learnt that
somebody else scanned it. Truthfully saying why — which this project insists on
everywhere else — is exactly what makes it an oracle.

It is closed by where the threshold sits rather than by refusing to answer. At
two scans the threshold was inside ordinary use: one person retrying after a
typo reached it, so the answer described a real user. At eight it is outside
anything this service sees, so a probe is answered "go ahead" and learns
nothing. Pushing the limit to where it speaks costs the prober eight scans of
the victim from several addresses — the very thing they were trying to detect,
performed by them, and visible in the victim's own logs.

Raising the threshold does not loosen what a scanned host carries. Sustained
load is set by the refill interval, not by the burst, and that has not moved;
and a single caller was never held by this limit anyway, because the per-client
limiter allows five scans a minute. What moves is the peak, which now takes
eight separate callers inside one window to produce.

The threshold is also varied per bucket from the per-process key, so even the
edge is not a fixed line to aim at.

What that varying does and does not buy is worth stating exactly, because it is
easy to claim too much for it. It hides the *count*: a probe measures the
allowance minus the prior scans and cannot separate the two terms, so being
served tells a prober nothing and being served twice tells them nothing more.
It cannot hide the *refusal*. Anyone who is refused has learnt one fact for
certain — that host has had at least `targetBurstMin` scans inside one refill
interval — and no arrangement of secret thresholds removes that, because the
refusal is the limit doing its job. Closing it would mean raising the minimum
again, and every point of the minimum is peak load the scanned server absorbs.
That residual is named in Known gaps and on the privacy page rather than left
to be found.

*Enforced in:* `internal/httpapi.targetBurstMin`,
`internal/httpapi.targetLimiter.burstFor`
*Guarded by:* `TestSecretBurstBlursAProbeFromOutside`,
`TestSustainedTargetRateDoesNotDependOnTheBurst`,
`TestBurstStaysWithinItsBounds`,
`TestBurstIsStablePerBucketAndSecretPerProcess`

---

## Privacy

### P1 — Nothing about a request is recorded

Not the target, not the client address, not the result. Addresses held for
rate limiting live in memory and are swept as they go idle.

This includes the parts nobody wrote. Go's `http.Server` logs lines such as
`http: panic serving 203.0.113.7` to standard error by default, so the server
must be given a discarding logger. A promise that depends on a library's
default staying convenient is not a promise.

A test cannot prove that no future line will ever be written, but it can fail
the moment one is, which is the difference between a promise and a habit. It
drives every path a request can take, because a line is usually added on the
unhappy ones.

*Enforced by:* the absence of logging in `internal/httpapi`, and
`httpapi.SilentErrorLog` passed to `http.Server.ErrorLog`
*Guarded by:* `TestNothingIsLogged`, `TestClientAddressesAreForgotten`

### P2 — The target travels in a request body, not a URL

A URL is written to browser history, to the `Referer` header of anything the
page later loads, and to the access log of every proxy on the path. Promising
not to record what was scanned while putting it in a URL hands that record to
everyone else.

*Enforced in:* `internal/httpapi`, `POST /api/v1/scan` only
*Guarded by:* `TestMethodAndPathRouting`

### P3 — Responses are never cached

A shared cache would hold what somebody scanned.

*Enforced in:* `internal/httpapi.setSecurityHeaders`, `Cache-Control: no-store`
*Guarded by:* `TestSecurityHeadersOnEveryResponse`

### P4 — Session resumption is not offered

A TLS session ticket is state the server hands to the client and reads back on
its next connection. Nothing is stored here — the state travels inside the
ticket — so it does not breach the promise about records directly.

It breaches it indirectly, which is worse for being harder to see. Anyone
watching the wire sees the same ticket presented twice and learns that two
connections are the same person: across a change of address, across a change
of network, across days. This project undertakes that nobody learns who asked
about what from us. Handing a third party the means to work it out instead is
the same undertaking broken by somebody else.

What it costs is a full handshake per connection. The site is four small files
and the certificate is ECDSA, so the exchange is one nobody will notice.

*Enforced in:* `cmd/denyfirstd` — `SessionTicketsDisabled`

---

### P5 — No plaintext listener exists

Nothing listens on port 80. A request that arrives there is refused by the
firewall, not answered by a redirect.

A redirect looks like the safer choice and is not. By the time a server can
answer, the client has already sent a request line and a `Host` header in
cleartext, and anyone on the path has read them. A closed port means the
request was never composed. The cost is that a client typing `http://` sees a
connection refused rather than a redirect, and for this domain no browser ever
will: `.dev` is on the HSTS preload list as a whole top-level domain, with
`include_subdomains` and `force-https`, so every browser rewrites the scheme
before a packet leaves the machine. There is no first insecure request to
protect.

The `preload` directive stays in the header even though this domain will never
be submitted, because it is already covered by its TLD. It is there for
whoever runs this code on a domain that is not: the correct header should be
the default rather than something an operator has to know to add.

Command line clients and HTTP libraries have no standardised HSTS handling, so
they do not benefit from either mechanism. They also do not type a scheme by
accident.

*Enforced in:* nftables, which opens 443 and nothing else; `denyfirstd` binds
one listener
*Guarded by:* `TestHeadersOnEveryResponse` covers the header; the absence of a
second listener is enforced by there being no flag that would create one

## Correctness of the report

### R1 — Verdicts come from the policy package and name their version

Grading logic anywhere else means the same server can be graded differently
depending on which code path reached it, and an upstream library changing its
opinion silently changes ours.

*Enforced in:* `internal/policy`; `tlsprobe` and `certinfo` only measure
*Guarded by:* `TestGradeCipherDelegatesToPolicy`, `TestReportNamesThePolicy`

### R2 — Every verdict cites a document, and the document is the current one

A verdict without a citation is an assertion. The reader must be able to
disagree with the standard rather than with us.

*Enforced in:* `internal/policy`, every rule carries `References`
*Guarded by:* `TestEveryFindingCitesASource`,
`TestEveryCertificateFindingCitesASource`

### R3 — What could not be measured is stated

Go's TLS stack offers roughly twenty-seven of the three hundred suites in the
IANA registry, and gives no way to choose among TLS 1.3 suites. A report that
omits this reads as exhaustive.

*Enforced in:* `internal/tlsprobe`, the `Notes` field
*Guarded by:* `TestSupportedVersionsCarryTheCoverageNote`,
`TestDescribeTransparencySeparatesTheFourSituations`

### R3a — Revocation is not checked, and the report says so

A chain reported as trusted reaches a root and is in date. It may still have
been revoked.

Checking would defeat the point of the service: asking a certificate
authority whether a serial is still good tells that authority which
certificate somebody is looking at, and querying a transparency log does the
same. No connection is ever opened to a responder.

*Enforced in:* `internal/certinfo.Analyse`, in the notes
*Guarded by:* `TestRevocationIsDeclaredUnchecked`

### R3b — A stapled response is reported, not believed

A status response that arrives in the handshake costs nothing to observe: it
is already on the wire and no third party learns anything. So the report says
whether one arrived.

It says no more than that. The response is not parsed, its signature is not
verified against the issuer, its dates are not compared against the clock, and
the serial it describes is not matched against the certificate in hand. A
report that prints "stapled" and stops has told a reader that revocation was
checked, which is the distance between an observation and a guarantee.

Absence of a staple is reported and not graded. The CA/Browser Forum no longer
requires certificate authorities to run OCSP and several have withdrawn it, so
a certificate issued now may name no responder at all; marking a server down
for failing to send a response nothing exists to produce would penalise a
correct configuration, which R6 forbids. The certificate's own CRL
distribution points decide which of the three sentences a reader gets, so the
report does not claim a list exists where none does.

One thing here is graded. A certificate carrying the RFC 7633 TLS Feature
extension has instructed clients to refuse the connection without a status
response. A server that then sends none is not falling short of an outside
recommendation; it is falling short of its own certificate, and clients that
honour the extension close the connection.

*Enforced in:* `internal/policy.GradeStapling`, joined in `internal/scan.Scan`
from `tlsprobe`'s observation and `certinfo`'s reading of the leaf
*Guarded by:* `TestGradeStaplingGradesOnlyTheBrokenPromise`,
`TestStapledNoteDoesNotClaimTheResponseWasChecked`,
`TestUnstapledNotesDistinguishThreeSituations`,
`TestListClaimIsNotMadeWithoutAList`, `TestMissingStapleIsNotAFinding`

### R3c — Transparency receipts are counted, not believed

A publicly trusted certificate has to be recorded in append-only logs, and each
log answers with a signed receipt. Those receipts reach a client three ways:
embedded in the certificate, sent as a handshake extension, or carried inside a
stapled status response.

Two of the three are read. The count and the number of distinct logs come from
the certificate and the handshake together, because a figure from either alone
misleads: almost every authority embeds them, so counting only the handshake
reports zero for a properly logged certificate, which is a claim that most of
the web is absent from certificate transparency.

Both numbers are reported rather than one. Browsers ask for receipts from
distinct logs so that a single misbehaving log cannot satisfy the requirement
alone, and three receipts from one log is a different situation from three from
three.

The second number is a union rather than a sum. Each route names the logs
behind its own receipts, and the usual arrangement is that both name the same
ones; adding two counts reports a log twice, which is how a certificate logged
in two places comes to be described as logged in four.

Nothing is verified. Checking a receipt needs the issuing log's public key, and
the set of qualified logs is a list browsers ship and revise; carrying a copy
would be a dependency on somebody else's judgement that goes stale between
releases. The report says the receipts were counted and not checked.

Nothing is graded either, for the same reason as R3b. The third delivery
channel is not read, so a certificate showing none by the first two may still
be presenting them by the third — and grading on two channels out of three
would fail a working configuration, which R6 forbids. How many receipts and
from which logs is in any case each browser's policy, revised on their
schedule, not ours to enforce.

Four situations are distinguished, because they look alike and are not: a
logged certificate, one outside the public authorities that owes nobody a
receipt, one whose receipts may be inside a stapled response nobody read, and
one a browser will refuse.

The list is parsed from attacker-chosen lengths — the certificate comes from
whatever host was named in the request — so every declared length is checked
against what remains rather than trusted, and a mismatch ends the parse rather
than being clamped to fit. There is a fuzz target.

The count sits on a line of the report and the caveat sits in the note, which
is not an accident of layout. The count is something this service measured and
measured exactly; that the receipts went unchecked against the issuing log's
key is something it did not do. On the same line the second reads as though
the first were uncertain.

*Enforced in:* `internal/certinfo.embeddedSCTs` for the count,
`internal/policy.DescribeTransparency` for what it means, joined in
`internal/scan.Scan`
*Guarded by:* `TestParseSCTListCountsTimestampsAndLogs`,
`TestParseSCTListRefusesMalformedInput`, `FuzzParseSCTList`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestLoggedNoteDoesNotClaimTheReceiptsWereVerified`,
`TestBothCountsAreReported`, `TestTransparencyReachesThePage`

### R4 — Nothing measured is not the same as passing, or as failing

An unreachable server is ungraded, not strong.

The second half was added on 2026-08-22, after the package was found giving
three different answers to one question. An unrecognised protocol version was
graded weak with a sentence saying it had not been graded, which is right. An
unrecognised cipher suite was graded **insecure** and told the reader its
session key came from a long-term key — a specific claim, invented, and false
of every TLS 1.3 suite that collected it. An unrecognised certificate key
algorithm was graded **strong** with a footnote, which is the same error
pointing the other way.

So the rule is symmetric now and stated as one sentence: what could not be
graded is weak, says it was not graded, and asserts nothing further about the
thing it could not read. Weak rather than ungraded, because `Worst` skips
ungraded and an unreadable suite would otherwise drop out of the aggregate
while the server that offered it was called strong.

*Enforced in:* `internal/policy.Ungraded`, `policy.Worst`,
`policy.GradeVersion` (`version.unknown`), `policy.GradeCipher`
(`cipher.unrecognised`), `policy.GradeLeaf` (`cert.key-algorithm-unrecognised`)
*Guarded by:* `TestNothingMeasuredIsUngraded`, `TestUnreachableTargetIsUngraded`,
`TestEveryStatedReasonIsTrueOfTheSuite`

### R4a — A verdict's stated reason is true of the thing it grades

A verdict is believed because it names a reason. Naming one that does not hold
is worse than declining to grade, and it is not caught by any check that a
grade is severe enough.

`FuzzGradeCipher` asserted that a suite graded strong really is forward-secret
and AEAD. That is the direction which fails safe for this service. The other
direction — that a suite told it has no forward secrecy really has none — was
unchecked, and `TLS_SM4_GCM_SM3` collected that sentence for two years of
policy versions while being a TLS 1.3 suite, where the property is guaranteed
by the protocol.

Every rule now declares what must be observable about a suite for its sentence
to be honest, and a rule added without such a declaration fails the test.

*Enforced in:* `internal/policy.cipherRules`
*Guarded by:* `TestEveryStatedReasonIsTrueOfTheSuite`,
`TestForwardSecrecyIsNeverDeniedOfASuiteThatHasIt`

### R4b — Trust and expiry are separate questions, asked separately

An expired certificate from an authority nobody trusts is not a trusted
certificate.

Go checks a certificate's dates before it looks for an issuer, so `Expired` is
the error it returns whether or not anything would ever have vouched for the
certificate. Reading that as "trusted apart from the dates" was right for a
real certificate past its renewal date and wrong for every self-signed or
private-CA certificate that had gone stale — which is what a scan of an
abandoned service finds. Three statements went wrong together: the trusted
flag, the suppression of `cert.chain-untrusted`, and a transparency note that
turned round to tell a private certificate that browsers refuse it for not
being logged.

The question is now asked again at the midpoint of the certificate's own
validity window, and that answer is the one reported.

*Enforced in:* `internal/certinfo.trustedWithinValidity`
*Guarded by:* `TestAnExpiredUntrustedChainIsNotReportedTrusted`,
`TestTrustWithinValidityAsksARealQuestion`

### R5 — One insecure option makes the configuration insecure

The attacker chooses which version and suite are negotiated, so aggregation is
worst-case rather than average.

*Enforced in:* `internal/policy.Worst`, used by `tlsprobe.summarise`
*Guarded by:* `TestWorstCaseAggregation`

### R6 — Correct configuration is not penalised

A server that refuses TLS 1.0 has done the right thing; grading the refusal
would report it as insecure. One problem produces one finding: a self-signed
certificate does not also raise chain-untrusted and chain-incomplete.

*Enforced in:* `tlsprobe.summarise`, `policy.GradeLeaf`, `certinfo.Analyse`
*Guarded by:* `TestUnsupportedVersionsDoNotContributeFindings`,
`TestSelfSignedDoesNotAlsoReportUntrustedChain`,
`TestPresentIssuerIsNotAnIncompleteChain`

### R7 — Results do not depend on the platform

Chain completeness is determined from what the server sent, not from whether
verification succeeded. On Windows and macOS the platform verifier fetches a
missing intermediate over the network; on Linux it does not. Reading the
verification result would make the same server complete on one machine and
incomplete on another.

What the rule did not cover, until 2026-08-22, was the sentence written beside
the result. A chain reported incomplete that verified anyway was explained as
"this platform's verifier fetched the missing certificate over the network" —
true on macOS and Windows, false on Linux, which is where this service runs.
The other explanation is that the issuer is in the trust store already. The
note now gives both and says which one applies is a property of the machine
that ran the scan, because that is all that was established.

The finding's own wording was also stronger than the measurement behind it. It
claimed the server "did not send every intermediate needed to reach a root",
while `chainComplete` looks only for the issuer of the leaf; a chain missing a
second intermediate passes it. Measured: leaf and one intermediate sent, the
next one omitted, `chainComplete` true, and a real client refusing the
connection. The finding now says what is checked.

*Enforced in:* `internal/certinfo.chainComplete`
*Guarded by:* `TestMissingIssuerIsAnIncompleteChain`,
`TestPresentIssuerIsNotAnIncompleteChain`

### R8 — Rules that change on a schedule are written as schedules

The CA/Browser Forum maximum certificate validity falls from 398 days to 200
on 15 March 2026, to 100 on 15 March 2027, and to 47 on 15 March 2029.
Compliance is judged at issuance, not at scan time, so a 398-day certificate
issued in January 2026 is valid and the same certificate issued in April is a
misissuance.

*Enforced in:* `internal/policy.MaxValidityDays`
*Guarded by:* `TestMaxValidityDaysFollowsTheSchedule`,
`TestValidityIsJudgedAtIssuance`

### R11 — A measurement that stopped early is not a measurement

Cipher enumeration makes one handshake for every suite a server accepts — up
to twenty-two at TLS 1.2. A host that rate-limits, resets, or simply tires of
answering will end that before the list does, and until 2026-08-22 every such
ending was read the same way as the one legitimate ending: the server saying it
had nothing left in common.

The direction of the error is what makes it serious. A Go server answers with
its strongest suite first, so a list cut short loses the weak end — the suites
that would have set the verdict. Measured: a server accepting two GCM suites
and two CBC suites was graded **strong** instead of weak when the connection
stopped answering after the second handshake. It also means the scanned host
can choose its own grade: answer twice, then go quiet.

Two things follow, and the second is the one that matters.

**Only the server saying no finishes a list.** A handshake failure alert, or
insufficient security, is the server having considered what was left. A
timeout, a reset, a refused connection, an unexpected close, or the round cap
is the question going unanswered, and the suites not yet reached stay unknown.

**An unfinished list forfeits `strong` and keeps everything worse.** The
asymmetry is the one R5 already rests on: worst-case aggregation only moves one
way, so a suite that was seen stays seen however the enumeration ended, while
the absence of anything worse is precisely what an unfinished list cannot
support. `Strong` is the verdict that claims an absence, so it is the one that
is withdrawn — to `Ungraded`, not to `Weak`, because the server has not been
shown to be doing anything wrong and R6 forbids grading a correct
configuration down for a connection that dropped.

The field is `CipherListComplete`, and its zero value is `false` on purpose. A
producer that forgets it gets `Ungraded` rather than a grade it did not earn.

*Enforced in:* `internal/tlsprobe.enumerateCiphers`,
`internal/tlsprobe.isNoSharedSuite`, `internal/tlsprobe.summarise`
*Guarded by:* `TestATruncatedSuiteListIsNotReportedAsComplete`,
`TestAnUnfinishedListCannotProduceStrong`,
`TestOnlyARefusalFinishesAnEnumeration`

### R10 — A report cannot act on the display that shows it

Every field taken from a certificate is text, and only text. Control
characters are replaced before the field is carried anywhere.

The bytes are chosen by the server being examined. Go parses a subject and its
alternative names as bytes and escapes only what X.500 requires, so an ESC
survives — and a terminal reads ESC as an instruction rather than as a
character. A subject of `\x1b[2K\x1b[1A    Verdict      strong` rewrites the
line printed above it, and the scanned server has edited the report about
itself. A tool whose argument is that it says only what it measured cannot
have its output written by the thing it is measuring.

The browser was never exposed: JSON escapes the byte and every value reaches
the page through `textContent`. Two other layers holding is not a reason to
pass it on, and the command line has neither of them. This is the rule
`dnsclient` already applies to a CAA value, which is attacker-chosen for the
same reason.

Replaced rather than dropped, so a reader can see that something was there.
The cut that bounds a long field lands on a character boundary for the same
reason: half a rune reaches a reader as corruption this report introduced.

**And the same attack aimed at the person rather than the pipe**, which this
rule missed until 2026-08-22. A control byte makes a terminal act; a Unicode
format character makes a reader misread, and neither is caught by a rule about
bytes below 0x20. U+202E reverses the display of everything after it, so a
certificate whose subject is `safe.test` followed by U+202E and
`moc.knab-live` is shown as `safe.testevil-bank.com` — by a terminal, and by a
browser, because `textContent` does not switch off the bidirectional
algorithm. The zero-width characters do the quieter version: `goo` U+200B
`gle.test` reads as `google.test` and is a different name. Measured: fifteen
such characters passed through untouched.

This is the published Trojan Source class, CVE-2021-42574, and it lands
squarely on a tool whose entire output is a claim about which name a server
presented. The whole Unicode `Cf` category is replaced rather than a list of
the dangerous ones, for the reason N1 gives about address families: a deny
list is worth exactly its completeness, and the characters added after this
was written would be on nobody's list. The cost is stated rather than hidden —
a subject legitimately using U+200D to join glyphs in an Indic or Persian name
renders with a replacement mark. A name shown imperfectly is recoverable; a
name shown as somebody else's is not.

*Enforced in:* `internal/certinfo.sanitise`, applied by `trimmer.text`
*Guarded by:* `TestControlCharactersInCertificateFieldsAreNeutralised`,
`TestC1ControlsAreNeutralisedToo`, `TestTrimmingCutsOnARuneBoundary`,
`TestNothingCanRewriteHowTheReportReads`

---

## The page

The frontend had no entry here while it was the only part of this project a
visitor actually runs. Two properties carry it, both load-bearing, and both
undoable in one line by somebody with a good reason.

### W1 — Nothing from a report reaches a markup parser

Every node is built with `createElement` and `textContent`. `innerHTML`,
`outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` and
`createContextualFragment` appear nowhere.

A successful scan returns the target the caller sent, by design, and hostnames
are attacker-chosen; so are a certificate's subject and its alternative names.
The moment one of those reaches a markup parser it stops being data. Building
nodes directly means there is no parser to reach: a string assigned to
`textContent` is a string, whatever it contains.

A test reads the shipped script and fails if any of those names appears. The
content security policy carries `require-trusted-types-for 'script'` and
`trusted-types 'none'`, which is the same rule expressed where a browser can
enforce it on the script that actually ran — the test checks the file this
repository ships, the header checks the thing in front of the user. Browsers
without Trusted Types ignore both directives, which costs nothing.

Class names come from one fixed list rather than from a value in the response.
A class is not a script, but it decides what the page looks like, and a page
that will paste any string into a class attribute has handed its appearance to
whoever answered. Two of the three places already did this and the third did
not, and the difference was invisible from either.

*Enforced in:* `internal/web/assets/app.js`, `internal/web.contentSecurityPolicy`
*Guarded by:* `TestScriptCannotInjectMarkup`,
`TestPolicyForbidsScriptReachingAMarkupParser`,
`TestScriptBuildsClassNamesFromOneList`

### W2 — The page loads nothing from anyone else

No analytics, no fonts from elsewhere, no content delivery network, no tag of
any kind: one stylesheet and one script, both from this server, both embedded
in the binary.

That held because nobody had added one. `Cross-Origin-Embedder-Policy:
require-corp` makes a browser refuse the resource if somebody does. Same-origin
subresources need nothing extra, so it costs nothing today and fails loudly
the first time the promise on the privacy page would stop being true.

*Enforced in:* `internal/web.setHeaders`
*Guarded by:* `TestNothingFromAnyoneElseIsEnforcedByAHeader`,
`TestContentSecurityPolicyAllowsOnlySelf`

---

## Disclosure

### D1 — A reporter can find a way to reach us, and the way is current

`security.txt` is served at `/.well-known/security.txt` over HTTPS, in the
format RFC 9116 defines. `/security.txt` redirects there rather than serving a
second copy, so the canonical URL in the file stays true.

The `Expires` date in that file is the only copy of it, and a test parses the
served bytes rather than a constant beside them. The test fails sixty days
before the date passes.

An expired `security.txt` is worse than none. A parser treats it as stale, and
a person reads it as a project that stopped paying attention — which is the
opposite of what publishing one is for. Sixty days is enough to notice a
failing build, decide the contacts are still right, and merge a change without
hurrying.

The file names `security@denyfirst.dev` for vulnerabilities and points a
domain owner at `abuse@denyfirst.dev` for exclusion requests. Those are
different queues: a takedown request sitting behind an embargoed report helps
nobody.

`Encryption` names an OpenPGP key served from `/pgp-key.txt`, and the key's
fingerprint is published twice: in `security.txt` and in `SECURITY.md` in the
repository.

Twice, because once proves nothing. A key served from this domain and
identified only by this domain is exactly what an attacker who takes the
domain would also serve — their key beside their fingerprint, and a reporter
encrypting an unpublished vulnerability straight to them. `SECURITY.md` sits
on GitHub behind a different account and different credentials, so a reporter
comparing the two is comparing two things that would have to fall together.

A test fails when the copies disagree, because two sources that agree only
because nobody checks are one source written twice.

The key certifies and encrypts and does nothing else, and is unrelated to the
release signing key, which is an SSH key pointing outward rather than in.

`security.txt` is not signed. A clearsigned file would be verified with the
key it points at, which answers nothing a forger could not arrange.

*Enforced in:* `internal/web`, the route table and `assets/security.txt`
*Guarded by:* `TestSecurityTxtIsServedAtTheWellKnownPath`,
`TestLegacySecurityTxtPathRedirects`, `TestSecurityTxtHasTheRequiredFields`,
`TestSecurityTxtExpiryIsMovedByAPerson`,
`TestSecurityTxtDoesNotSendExclusionRequestsToSecurity`

### R9 — Issuance policy is reported and not graded

A CAA record names the authorities allowed to issue certificates for a domain.
Without one, any of around a hundred publicly trusted authorities may, which
means the weakest of them sets the standard. Checking it has been mandatory
for authorities since 2017, and it is one of the few controls a domain owner
can apply to authorities they have no relationship with.

It is reported and not graded, and the reason is where it comes from rather
than what it says. Everything else this policy grades arrives in the
handshake: a protocol version, a cipher suite, a certificate. This arrives
from a resolver, over a path nothing here authenticates, describing a system
the person who configured the server often does not administer. A verdict on
the transport that moved because of a DNS record would be a verdict about
somebody else's zone.

The answer is reported as what it is. Not "this could not be measured" — it
was measured, by asking a resolver, and the resolver answered. The note says
which resolver, how far up the tree the search went, and whether the answer
carried the AD bit. That bit is the resolver's claim to have verified the
DNSSEC chain and not this service's, and its absence is ambiguous by
construction: an unsigned zone and an answer nobody validated look the same
from here, and most zones are unsigned.

**A walk that ran out of budget is a tenth state, and it was reading as the
one that means the opposite.** CAA is inherited, so the search goes label by
label towards the root, and the budget bounds it. A walk that reached the top
and found nothing means any authority may issue; a walk that stopped partway
means the name carrying the policy was never asked. Both produced an empty
record list, and the report published the first sentence for both. At the old
budget of four, `a.b.c.d.example.com` was searched as far as `d.example.com`
and reported as unrestricted, while a policy on `example.com` would have
governed it. The budget is six now, which covers seven labels, and
`Answer.Complete` says when it still stopped short.

Ten states are distinguished, and a test fails when two of them read the
same. One exists because `microsoft.com` publishes a record set carrying only
`contactemail`: a CAA record set exists, no `issue` property is in it, and
nothing is restricted. A report saying CAA is present would have been true and
useless. That state was found by pointing the client at live hosts, not by
reading the RFC.

The line goes on the face of the report rather than into the notes, which fold
shut under every verdict but ungraded. For a name with no CAA it is often the
most useful sentence in the report: one DNS record, nothing to break by adding
it, and a hundred authorities that stop being able to issue.

It sits above the transparency line because the two are halves of one question
in the order the halves happen. A restriction is checked by an authority at
the moment it issues, so it does not help against a resolver poisoned at that
moment or an authority that has itself been compromised; the logs record the
result either way.

The lookup runs last and is bounded by what remains of the caller's deadline,
so a scan that spent its time on handshakes reports the check as not made
rather than running over. Every failure produces the same description, because
none of them is a fault of the name being scanned.

*Enforced in:* `internal/dnsclient` for the query,
`internal/policy.DescribeIssuance` for what it means, joined in
`internal/scan.Scan`
*Guarded by:* `TestDescribeIssuanceSeparatesEveryState`,
`TestNotCheckedIsNotAnAccusation`, `TestProvenanceIsAlwaysStated`,
`TestEveryCheckedStateMentionsTransparency`, `TestNoRecordSaysWhatFollowsFromIt`,
`TestIssuanceIsOnTheFaceOfTheReport`, `TestIssuanceSitsAboveTransparency`,
`TestAnUnfinishedWalkDoesNotClaimNobodyIsRestricted`

### N5 — A resolver's reply is treated as hostile

The CAA lookup builds its own DNS message, because the standard library
exposes no general query. Everything it reads comes over plaintext UDP, where
whoever answers first is the resolver.

The question carries a random identifier and randomised letter case, and the
reply is compared against it byte for byte: a forger who did not see the
request cannot reproduce it, and DNS comparison is case-insensitive so the
randomisation costs nothing. Compression pointers may only point backwards and
their number is capped — two rules where one would do, because a name pointing
at itself is the bug every hand-written DNS parser has had at least once.
Every declared length is checked against what remains rather than clamped to
fit. A CAA value that is not printable is refused rather than passed on.

A record is read only if its owner name is the name that was asked about.
Everything above establishes that the message came from something that saw the
query; none of it establishes that the records inside describe the right name.
A resolver — hostile, broken, or expanding a CNAME this client does not follow
— can put another name's record set in the answer section, and read without
this the report presents that other name's policy as this one's. The
comparison folds case, because the query randomises it on purpose and a
byte-for-byte match here would discard every legitimate answer.

SERVFAIL is not an empty answer. It is what a validating resolver returns when
a signature does not check out, and reporting it as no records would turn a
broken DNSSEC chain into a clean result.

*Enforced in:* `internal/dnsclient`
*Guarded by:* `TestReplyMustAnswerTheQuestionAsked`,
`TestResponseCodesAreNotAllTheSame`, `TestCompressionPointersCannotLoop`,
`TestMalformedRecordsAreRefused`, `TestQuestionCaseIsRandomised`,
`TestRecordsForAnotherOwnerAreIgnored`, `TestOnlyTheAskedForOwnerIsKept`,
`TestOwnerMatchingIsCaseInsensitive`, `TestCompressedOwnerNamesMatch`,
`FuzzParseReply`, `FuzzSkipName`

## Supply chain

### S1 — No third-party dependencies

`go.mod` has no `require` block. The CI workflow uses no third-party actions:
checkout is four lines of git, and the Go toolchain downloads itself.

*Guarded by:* `go mod verify` and the tidy check in CI

### S2 — Known vulnerabilities block a release

`govulncheck` reports only what is reachable from this module's code, so a hit
is a real problem rather than a version-range guess. Because this project uses
`crypto/tls` and `crypto/x509` heavily, and Go issues security releases
roughly monthly, this check will fail periodically. That is the mechanism
working.

*Guarded by:* the `Known vulnerabilities` job in CI

### S3 — The procedure that builds a release is pinned to that release

A signature says the artifacts came from whoever holds the key. Building in
public and signing on a separate machine is what makes it also say they
correspond to the source, and that argument has a hole if the build command
itself is mutable.

It was. Both the release build and the reproduction fetched
`scripts/build.sh` from the default branch at run time, so somebody able to
move that branch could change what a tagged, honest commit compiled into — and
the reproduction, reading the same file, would rebuild the same altered bytes
and report a match. Two parties were involved and both consulted the same
mutable third.

Three things close it. The tag's own script is used when it has one. The hash
of whichever script ran is recorded in `BUILD`, and the reproduction refuses
to proceed unless the script it holds hashes to that value. And the signing
script refuses to sign unless that hash is one this repository contains.

`BUILD` is written before the checksums are taken, so it is listed in
`SHA256SUMS` and therefore covered by the signature. It used to be written
afterwards, which left the provenance record unsigned while the reproduction
used it to decide whether a mismatch was tampering or a different toolchain.

**v0.1.0 is outside this and will always be.** It was cut before both the
script and the `buildscript` field, so nothing records what produced it.
`reproduce.yml` was dispatched against it on 2026-08-20 — the first time it had
ever run — and refused: no field to compare the script against, therefore no
statement it could honestly make. That refusal is the invariant holding, not
breaking. A reproduction that cannot name the procedure it reproduced would be
reporting agreement with itself.

*Enforced in:* `.github/workflows/build-release.yml`,
`.github/workflows/reproduce.yml`, `scripts/release.ps1`

### S4 — A published release cannot be replaced by a workflow

The release build replaces a draft, because a rerun after a failure must not
leave half of one attempt beside half of another. It refuses to touch a
published one: `gh release view` finds those too, so the check that looked for
"a release for this tag" deleted signed releases — signature and all —
whenever the workflow was dispatched with a tag that had already shipped.

Rebuilding is a recovery step. Deleting what users are verifying against is
not.

*Enforced in:* `.github/workflows/build-release.yml`

### S5 — There is one build command, and it is the one the documents name

S3 pins the build procedure to the release. That pin is worth exactly as much
as the number of copies of the procedure there are, and there were three: the
script itself, a transcription inside `scripts/release.ps1` that the maintainer
runs to check a release before signing it, and a third in `docs/verify.md` that
a stranger runs to check it afterwards.

The third had drifted. It named `-X main.version=v0.1.0`, a symbol this program
does not define. Go accepts an unknown `-X` without a word and folds the whole
link command into the build ID, which it writes into the binary; so the
published instructions for proving a release untampered produced a hash that
differed from the published one — on the right source, with the right compiler,
for everybody who followed them. Measured: identical size, forty bytes apart,
all of them in the build ID notes.

That is the worse direction for this to fail in. It does not conceal tampering,
it manufactures it, and a check that reports tampering on every honest release
teaches its readers to disregard the one that does not. The same script's own
header had said as much about a different pair of copies since the day it was
written.

Both transcriptions are gone. `release.ps1 -Compare` now extracts the script
whose hash `BUILD` records and runs that, refusing to compare at all if it
cannot — a comparison that quietly did not happen reads, three lines later,
exactly like one that passed.

*Enforced in:* `scripts/build.sh`, `scripts/release.ps1`, `docs/verify.md`
*Guarded by:* the `One build command, and a release script that parses` job in
CI, which fails if the release build flags appear anywhere but
`scripts/build.sh`

### S7 — The toolchain is a supported one, and the analysis gates still run

Go supports each major release until two newer ones exist. On 2026-08-22 that
made the supported lines 1.27 and 1.26, and this project was on 1.25.13 —
receiving no further security fixes, while being built almost entirely on
`crypto/tls` and `crypto/x509`.

The `go` directive is the only place a version is named. Nothing pins a
toolchain in CI, in `scripts/build.sh`, or on the server, so one line moves all
three: an older toolchain downloads the named one through the module mechanism
and re-execs it, verified against the checksum database.

**1.26.7 rather than 1.27.0, and the reasoning is worth keeping.** Both are
supported, so the security argument is satisfied either way. 1.27 costs
something: staticcheck's newest release, 2026.1 (`v0.7.0`), supports Go 1.26,
and no release yet reads a 1.27 module. Measured on the branch — `Build and
test` passed on 1.27 while `Static analysis` and `Known vulnerabilities` both
failed. Trading a static analysis gate for a security benefit that 1.26.7
already provides is not a trade. Move to 1.27 when staticcheck ships support,
and check at every review whether it has.

The three GODEBUG settings 1.27 removes — `tlsrsakex`, `tls3des`,
`tls10server` — all govern defaults, and this scanner sets `MinVersion` and
`CipherSuites` explicitly, so the eventual move costs nothing in what it can
detect. Measured: explicit `MinVersion` reaches TLS 1.0 and 1.1, and the
library still lists seven static-RSA and two 3DES suites.

*Enforced in:* `go.mod`
*Guarded by:* the `Build and test`, `Static analysis` and `Known
vulnerabilities` jobs in CI, which is where the 1.27 attempt was caught

### S6 — What reaches `main` is what was signed

Everything above rests on being able to say who wrote a line. Commits are
signed with an SSH key, and `.github/commit-signers` publishes the public half
so that anybody can check, rather than only GitHub.

The part that had to be learnt: **the merge does this, not the checks.** Every
check runs against the branch, and the merge happens afterwards, so a merge
that rewrites the commits rewrites them after the last thing that could have
objected.

- **Merge commit** — the branch's commits enter `main` byte for byte, keeping
  their signatures. GitHub adds one commit of its own on top, signed with its
  own key; it carries no content, only two parents.
- **Squash** — GitHub writes one new commit and signs it. The originals never
  reach `main`, so what is on the branch is what the maintainer signed and what
  is on `main` is what GitHub says they signed.
- **Rebase** — a signature covers the parent hash, and rebasing changes the
  parent, so the signature cannot survive. GitHub does not re-sign. The commits
  arrive unsigned.

On 2026-08-20 this project used all three across three pull requests and got
three different answers, the last of which put four unsigned commits on `main`
past ten green checks. They are `1fdf674`, `cc163a3`, `01fc49f` and `7cd2cfa`;
the same trees, signed, are the tag `signed/2026-08-20-docs-and-build`, and
`git diff` between the two is empty. That is stated here rather than repaired,
because repairing it means allowing a force-push to `main`, and a branch that
accepts force-pushes for a minute is a worse thing to own than four commits
whose provenance is recorded one ref away.

Squash and rebase merging are disabled in the repository settings. That is not
a thing a test can assert from inside a checkout, so it is written here, and it
is the first thing to re-check if this ever happens again.

*Enforced in:* the repository's pull request settings (merge commits only);
`.github/commit-signers`
*Guarded by:* the `Every commit in this pull request is signed by a known key`
job in CI, which covers commits arriving on a branch and explicitly does not
cover what a merge does to them afterwards

---

## Known gaps

Listed rather than hidden. An unnamed gap is a surprise; a named one is work.

A stale list is worse than no list, because a reader takes it as current. Four
entries were removed when this was last read: the server binary, the pinned CI
tools, release signing, and fuzzing all exist now. Two more went at the review
after that: P1 has a test, and the flag that could not take effect was removed
rather than fixed. One more goes now — "no independent review" — because that
review has happened. What it found is written into the rules above rather than
summarised here: A6 to A9, R10, S3 to S5, W1 and W2 all exist, or say what they
now say, because of it. Leaving the entry in place would have been this
document doing, on its own front page, the thing it warns about. Anything below
is open today.

- **Transparency receipts are counted and not verified.** R3c. Checking one
  needs the issuing log's public key, and the qualified-log list is maintained
  by browsers on their own schedule.
- **A stapled response is observed, not validated.** R3b. Verifying one needs
  an OCSP parser and a signature check against the issuer, and this project
  carries no dependency that would provide either.
- **The published key is not verifiable from the served bytes.** D1. The test
  compares the fingerprint across its two published copies; it does not
  compute the fingerprint of the key file, which would need an OpenPGP parser
  and SHA-1. A key file swapped without touching either copy would pass.
- **An address family that cannot be reached is not named.** The dialler
  resolves both families and tries up to eight addresses. On a host with IPv6
  disabled, a target with many AAAA records can spend that budget on
  unreachable addresses and be reported as unreachable, with no note saying
  why. R3 requires the opposite.
- **The per-target limit still answers at its edge.** A9. The threshold now
  sits outside ordinary traffic, so a probe learns nothing about a person; what
  remains is that a host genuinely being checked eight times in a window can be
  observed to be busy. That is a fact about load rather than about anybody, and
  its own administrator can already read it in their logs. The secret spread
  hides how many scans there were; it cannot hide that there were at least
  `targetBurstMin`, because that is what the refusal means. Closing that would
  mean raising the minimum again, which spends a scanned host's peak to buy a
  stranger's privacy — a trade this project will not make on a third party's
  behalf without saying so, which is why it is also on the privacy page.
- **Truncation defends enumeration, not confirmation.** A bucket identifier
  cannot be turned back into a name. It was never a defence against somebody
  who already suspects one name and tests it, and the comment in
  `targetlimit.go` used to imply otherwise by claiming billions of names per
  bucket; against a realistic candidate list twelve bits gave two hundred
  thousand, and sixteen gives fifteen thousand. The figure is corrected and
  the limit of what it protects is now stated.
- **`scan_failed` cannot be reached.** A7. `scan.Scan` cannot fail once the
  handler has validated the target, so the branch is defensive. Named in
  `TestEveryRefusalCodeCanBeProduced` rather than left to be discovered, and
  the test fails if the list of such codes grows without an explanation.
- **One reader is not an audit.** The rules above came from one careful
  reading, not a funded engagement. It has now covered `internal/policy` and
  `internal/certinfo` as well, which were its thinnest ground and turned out to
  hold the errors that mattered most — a prohibited suite graded strong, a
  verdict whose stated reason was false, and a certificate reported trusted
  because Go stopped checking at the dates. What remains unread by anyone but
  the author is `internal/tlsprobe` and `internal/dnsclient` below the parsing
  that was already reviewed.
- **Finite-field DHE cannot be observed at all.** `cipher.ffdhe` grades it, and
  this scanner will never present it a suite to grade: Go offers no FFDHE
  cipher suites, measured as fifteen ECDHE and zero FFDHE. A TLS 1.2 server
  configured for finite-field DHE alone is therefore measured as accepting
  nothing, and the report does not distinguish that from a server that refused
  everything for its own reasons. The rule is right and unreachable through
  this front end, which is worth stating rather than counting as coverage.
- **A name can still be spelled in a lookalike alphabet.** R10 now replaces
  every Unicode format character, which stops a certificate from reordering or
  hiding what the report shows. It does nothing about a subject using Cyrillic
  `а` where Latin `a` is expected: the two are different characters that render
  identically, and normalising them away would corrupt every legitimate name in
  those scripts. Hostname matching is unaffected — it compares bytes — so this
  is a question of what a reader sees rather than of what was verified.
- **Only the newest version's certificate chain is described.** The chain is
  taken from the most modern handshake that succeeded, and a server may present
  a different certificate at a different protocol version — selection by
  offered signature algorithms is a real configuration. A chain served only to
  TLS 1.0 clients is not seen, so a SHA-1 certificate reachable that way would
  go unreported while the report describes the modern one.
- **Extended key usages Go does not name are not reported.** A certificate
  carrying an EKU outside the seven the standard library has constants for puts
  the OID in `UnknownExtKeyUsage`, which this report does not read. The field
  reads as though the certificate carried nothing else.
- **Four commits on `main` carry no signature.** S6. `1fdf674`, `cc163a3`,
  `01fc49f`, `7cd2cfa` — rebase-merged, which strips the signature the author
  put on them. The signed originals are the tag
  `signed/2026-08-20-docs-and-build` and the trees are identical, so the
  provenance exists; it is one `git diff` away rather than in the log, which is
  not the same thing. Closing it needs a force-push to `main`, and opening that
  door costs more than the four commits are worth.
- **No release has been reproduced.** S3. `reproduce.yml` has now been watched
  — dispatched by hand against v0.1.0 on 2026-08-20 — and it refused, correctly,
  because that release predates the record of what built it. So the workflow is
  known to run and known to fail closed, and the property it exists to
  demonstrate is still undemonstrated: no release in this project has been
  rebuilt byte-for-byte by a second party. That waits on the next tag, which
  will carry both the script and the `buildscript` field.
- **`release.ps1 -Compare` has not run end to end.** The bash path was exercised
  by hand on 2026-08-20 and built all ten artifacts, which is most of it, but
  the surrounding script — download, verify, compare, sign — has not been run
  as one piece since it changed. The first time must not be a release evening.