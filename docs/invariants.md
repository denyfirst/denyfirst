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

A limit of this scan and a limit of this program are different claims, and
until 2026-09-01 they were printed under one heading with everything the scan
had established. R18 is what separates them; this invariant is what requires
them to be said at all.

*Enforced in:* `internal/tlsprobe`, the `Notes` field
*Guarded by:* `TestSupportedVersionsCarryTheCoverageNote`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestEveryNoteInAReportCarriesAKind`

### R3a — No authority is asked, and the claim about revocation is made where the answer is known

A chain reported as trusted reaches a root and is in date. It may still have
been withdrawn.

No connection is ever opened to a responder. Asking a certificate authority
whether a serial is still good tells that authority which certificate somebody
is looking at, and querying a transparency log does the same. That much has
never changed and is true on every branch.

What changed is everything after it. Until 2026-09-01 this invariant read
*revocation is not checked, and the report says so*, and `internal/certinfo`
appended that sentence to every report it produced. It was written when
nothing here parsed a stapled response. **R3b, directly below, records that
v0.3.0 made this project read one and verify it against the issuer** — so from
that release the two invariants on this page contradicted each other, and so
did the report: a stapling server was told *Revocation was not checked*
directly above *The stapled response was read and verified*. Around a third of
the hosts measured here staple. The contradiction survived a release, a policy
version and a public deployment.

Two things kept it alive, and both are worth naming. The sentence lived in a
package that cannot know the answer — whether a response verified is settled
in `policy.GradeStapling`, and a sentence written where the answer is unknown
is a sentence that cannot be made conditional. And a test asserted the words,
so the change that made them false left the test green. That is the third time
in this repository a test has held a stale sentence in place by nailing its
prose, and the rule it produced is applied here: assert the property, in the
package that can establish it.

The claim now sits in `policy.GradeStapling`, which has every outcome and a
sentence for each, with one standing note across all of them saying no
authority is asked. `internal/certinfo` says nothing about revocation at all,
and a test enforces that it does not.

*Enforced in:* `policy.GradeStapling`, in the notes
*Guarded by:* `TestNoAuthorityIsAskedOnAnyStapleOutcome`,
`TestThisPackageClaimsNothingAboutRevocation`

### R3b — A stapled response is read, and what reading it cannot settle is said

A certificate stops deserving trust before it expires when its key is stolen,
when it was issued in error, or when a domain changes hands. Revocation is the
mechanism, and a stapled OCSP response is the authority's signed statement
that a certificate was not revoked as of a moment — handed to the client by
the server, so the client never tells the authority which site it is visiting.

Until 2026-08-22 this project observed that bytes arrived and reported *a
status response was stapled*. It parsed nothing. A server can staple anything:
an empty file, a year-old response, a response about a different certificate,
one signed by nobody, or one that says revoked. Every one of them produced the
same sentence, and a reader takes that sentence to mean revocation was
checked.

The direction is the worst available. Revocation is the emergency brake of the
whole system, and the case it exists for — a certificate that really has been
withdrawn — is exactly the case a server has a motive to paper over by
continuing to staple the last response that said good.

**Four things have to hold before a status is reported.** The responder
answered successfully with a basic response. The entry describes *this*
certificate, by issuer name hash, issuer key hash and serial number, all
three — the serial alone is unique per authority rather than globally, and the
issuer hashes alone describe every certificate that authority ever signed. It
was produced in the past and has not expired. And it is signed by the issuer,
or by a responder the issuer both signed and marked with the OCSP-signing
extended key usage — without that second condition any certificate the
authority ever issued, including the one being checked, could vouch for its
own revocation status.

Anything else is a response that establishes nothing, reported as such, and
never as good news.

**What still is not checked, and why it stays that way.** The responder
certificate's own revocation status. Checking it means fetching another
response, over the network, from an address the scanned party chooses; nothing
in this package fetches anything, and only bytes the server already sent are
read. RFC 6960 §4.2.2.2.1 lets an issuer waive the check, and responder
certificates carry short lifetimes for that reason.

**A missing issuer is not a failure of the response.** Every check is against
the issuer, so a chain that omits it establishes nothing — and produces no
finding here, because `cert.chain-incomplete` already grades the omission and
charging one mistake twice reports it as two.

Everything this reads is chosen by the scanned server, which makes it the most
hostile input this project accepts and the only cryptographic parser it owns.
It is bounded at every length, it returns errors rather than panicking, and it
is fuzzed on the nightly schedule.

One more thing decides whether any of it runs against the right certificate.
Every check is against the issuer, and the issuer used to be taken as
`chain[1]` — the second certificate the server sent. RFC 8446 dropped the
requirement that a chain be ordered: a sender SHOULD order it and a receiver
MAY accept any order, so a server sending an unrelated cross-signed
alternative first is not doing anything wrong. Taking the wrong one there
produces a `cert.staple-unverifiable` finding against a server doing
everything right, which is the false-accusation direction again. The issuer is
now found by checking which certificate in the chain actually signed the leaf.

The certificate section says which of those happened, and for a policy version
it did not. `internal/ocsp` landed, the notes and the findings were rewritten,
and the one line a reader looks at for revocation went on saying *a status
response was stapled* — the sentence the whole round existed to replace. The
same defect as R12, in the same file, one round later, found by reading a live
report rather than by any test. `StapleFinding` now carries the outcome as
serialised fields rather than leaving a front end to infer it from a rule
identifier, and a test requires the page to read them.

*Enforced in:* `internal/ocsp.Check`, `internal/policy.GradeStapling`,
`internal/scan.issuerOf`, `internal/web/assets/app.js` (`revocationText`)
*Guarded by:* `TestAGoodResponseIsRead`, `TestARevokedCertificateIsReported`,
`TestAnUnknownStatusIsNotGood`,
`TestAResponseAboutAnotherCertificateIsRefused`,
`TestAResponseFromAnotherAuthorityIsRefused`,
`TestAnExpiredResponseIsRefused`, `TestAResponseFromTheFutureIsRefused`,
`TestAResponseSignedByNobodyIsRefused`, `TestADelegatedResponderIsAccepted`,
`TestACertificateCannotVouchForItselfWithoutTheDelegation`,
`TestAResponderFromAnotherAuthorityIsRefused`,
`TestAnUnsuccessfulResponseIsNotAStatus`,
`TestWithoutTheIssuerNothingIsClaimed`,
`TestRubbishIsRefusedWithoutPanicking`,
`TestAnUnknownResponseTypeIsRefused`,
`TestTheStapledNoteSaysWhichOfTheThreeHappened`,
`TestTheShapesRealRespondersEmit`, `TestTheRightEntryIsFoundAmongSeveral`,
`TestRealResponsesFromRealAuthorities`,
`TestTheFixturesCoverBothSigningArrangements`,
`TestTheIssuerIsFoundWhereverItSitsInTheChain`,
`TestTheRevocationLineSaysWhetherTheResponseWasVerified`, `FuzzCheck`

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

### R3d — A limit of this scanner's network is not a fault of the server

A name that publishes only AAAA records is unreachable from a host with no
IPv6 route, however healthy the server is. The report said *the host could not
be reached* — a statement about somebody else's server, arrived at from a fact
about this one.

`safedial` now records which address families it actually attempted, after the
policy check rather than before it, so an address refused for being private
does not count as a family that was tried. When every attempt used one family
and none of them answered, the failure carries that family, and the reply says
so: *the host could not be reached, and every address published for this name
is IPv6; a scanner with no IPv6 route reaches none of them.*

Two things are deliberate about that sentence. It names a property of the
**target's** DNS rather than of this machine, so I6 still holds: what is
published in a name's own records is checkable by the reader in a second, and
what this scanner has configured is nobody's business. And it is said only
where it can be the explanation — a refused connection or a reset proves the
path works, and neither reaches the branch that adds it.

The check is symmetric. An IPv6-only network reaching an IPv4-only name has
exactly the same problem, and writing the rule for one family because the
other is rarer is how a scanner comes to be correct only on the machine it was
written on.

*Enforced in:* `internal/safedial.SingleFamilyError`,
`internal/safedial.soleFamily`, `internal/tlsprobe.classifyHandshakeError`
*Guarded by:* `TestASingleFamilyIsNamedAndAMixedOneIsNot`,
`TestTheFamilyWrapperHidesNothing`,
`TestAnUnreachableHostSaysWhichFamilyWasTried`

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

### R12 — A failure to measure is never drawn as a measurement

R11 settled this inside the probe. This is the same rule at the two places a
person actually reads: the page and the terminal. Four ways it was broken were
found on 2026-08-22, all in rendering, none visible from the packages that get
the facts right.

**A version row said `refused` whenever the handshake did not succeed.** Only
one kind of failure is a refusal — the server answered and declined. Our own
client not offering a version, a name that did not resolve, a timeout, a reset,
a destination the service will not dial: every one of them leaves `Supported`
false as well, and every one of them was printed as a refusal. The direction is
what makes it serious rather than untidy. *"TLS 1.0 refused"* is a row in the
server's favour, and both front ends were awarding it on the strength of a
handshake that never took place. `tlsprobe` had already written the careful
sentence — *"not tested: this build of Go declined to offer TLS 1.0"* — and the
page discarded it while the terminal printed it in the same line as the word it
contradicted.

**A truncated cipher list was drawn under a heading that claims completeness.**
R11 withdraws `Strong` when enumeration stopped early and raises a note saying
so, but the note lives in a block the page keeps shut under every verdict except
`Ungraded`. Under a weak or insecure verdict the reader met a table headed
*"Cipher suites accepted"* with nothing on it to say the weak end was never
reached. The mark now sits on the table.

**Receipts that could not be read were counted as though they had been.** A
transparency timestamp too short to hold a log identifier contributes to the
total and to no log, so a certificate whose timestamps were all unreadable
produced *"3 timestamps from 0 logs"* — this scanner reporting its own failure
in a sentence shaped like a fact about the certificate.

**The sentence bounding what this client offers was attached to success.** A
server speaking only suites Go does not implement answers every probe with a
handshake failure, which is the same alert as a version refusal; every row then
reads `refused`, and the note explaining that a refusal here is not proof the
version is switched off was skipped precisely because nothing had been
accepted.

The general form, and the thing to check when a field is added: **a bit saying
a measurement failed has to exist in the data rather than be inferred from the
absence of a result, and every renderer has to read it.** `Refused` exists for
that reason and carries no `omitempty`, for the same reason `CipherListComplete`
does not.

The smallest instance of this is worth keeping, because it took no protocol
knowledge to make and none to miss. `cert.serial-entropy` reads a bit count,
and a bit count of zero means two things: a serial that is zero, and a serial
nobody read. The first version of the rule fired on both, so every certificate
whose facts were built by hand without a serial was accused of carrying a
counter. The existing tests in the package caught it on the first run. The rule
now requires a measurement before it says anything, and a serial that really is
not positive is reported as a note, because a malformed field and an unread one
are not the same finding either.

*Enforced in:* `internal/tlsprobe.VersionResult.Refused`,
`internal/tlsprobe.classifyHandshakeError`,
`internal/tlsprobe.suiteCoverageApplies`, `internal/web/assets/app.js`
(`outcomeCell`, `ciphers`, `transparencyText`),
`cmd/denyfirst-scan.printVersions`, `cmd/denyfirst-scan.printCiphers`
*Guarded by:* `TestOnlyAServerRefusalIsCalledOne`,
`TestATruncatedListSaysSoWhereItIsShown`,
`TestAVersionThatCouldNotBeMeasuredIsNotCalledRefused`,
`TestATruncatedCipherListIsMarkedOnTheTable`,
`TestUnreadableTimestampsDoNotBecomeAMeasurement`,
`TestTheLimitsOfThisClientAreStatedWhenNothingWasAccepted`,
`TestTheClassesTheScriptAddsAreStyled`, `TestClientRefusalIsNotServerRefusal`,
`TestAVersionThatCouldNotBeMeasuredIsNotDrawnAsRefused`,
`TestASerialTooSmallToBeRandom`,
`TestThePostQuantumQuestionHasThreeAnswers`

### R13 — An exit status is a verdict, and `ungraded` is not zero

`denyfirst-scan` exists partly to gate a pipeline, and its status was the one
reader of a verdict that could not be corrected afterwards. It exited `0` on
`Ungraded`.

That is the whole of R11 undone at the shell. An unfinished enumeration
withdraws `Strong` and returns `Ungraded` — and the host decides when to stop
answering, so `Ungraded` is a state the party being gated can choose. Answer
twice, go quiet, exit zero, pipeline green. The protection ended one layer
before the only layer that acts on it.

There was a second half. `policy.Worst` ignores `Ungraded` entries, correctly:
aggregating grades has to skip the things that are not grades. Reading the
status off it alone therefore published a pass for a target nobody measured
whenever another target in the same run came back clean.

`Ungraded` now has a status of its own, `4`, ranked below a weak or insecure
finding — an operator with both is sent to the finding first — and above a
clean run. The decision is a function of the results rather than a switch at
the end of `run`, so it can be exercised without a network.

*Enforced in:* `cmd/denyfirst-scan.exitCode`
*Guarded by:* `TestUngradedIsNotAPass`,
`TestAnUngradedTargetIsNotHiddenByAGoodOne`,
`TestSeverityOutranksAnAbsentResult`

### R14 — A chain reachable at any version is a chain reachable

A server picks its certificate from what the client offered, so an old client
can be handed a different one — and the chain kept for old clients is the one
most likely to be weak. This report took the chain from the newest handshake
that completed and described that, which meant a SHA-1 or small-key
certificate sitting behind TLS 1.0 was invisible beside a clean modern chain,
in a report whose subject is exactly that kind of leftover.

R5 settles what to do about it. An attacker chooses which version to
negotiate, so a certificate reachable at any version is a certificate
reachable, and the worse of the two has to set the verdict.

Every version that completed a handshake is compared by its leaf's own DER
bytes — not by subject, serial or names, each of which a server can repeat
across two genuinely different certificates. A chain whose leaf is not the
leaf already described is analysed in full, its findings join the list, its
notes name the version and the certificate by fingerprint, and its verdict
joins the aggregate. Two versions served the same second certificate count
once.

What the report still shows in detail is the newest handshake's chain, because
that is the one nearly every visitor's browser is given. The note says the
other exists and what it is; the findings say what is wrong with it.

Two handshakes to an ordinary server return the identical certificate, so in
the ordinary case nothing here runs.

*Enforced in:* `internal/tlsprobe.differingChains`, `internal/scan.Scan`,
`internal/scan.Result.Findings`, `internal/scan.Result.Notes`
*Guarded by:* `TestAChainServedOnlyToOldClientsIsSeen`,
`TestOneCertificateForEveryVersionProducesNoAlternate`,
`TestAWeakCertificateBehindAnOldVersionIsGraded`


### R15 — A rule that cannot fire is named, not counted

A rule set is read as a list of what a scanner checks. Some of these rules
cannot fire here at all: the front end is Go's TLS client, which offers what it
implements, and a rule matching a suite Go does not implement will never see
one. It is still correct — it is simply not coverage, and the difference
matters to anyone deciding whether this report is enough.

The Known gaps said this of exactly one rule, `cipher.ffdhe`, because somebody
noticed it. Measuring the rest found nine of thirteen cipher rules in the same
position, and two of three version rules. A list naming one case out of nine
reads as though the other eight do not exist, which is worse than naming none.

So the set is measured rather than remembered. Everything this prober can offer
— every version in `probedVersions`, every suite in `candidateSuites` — is
graded, the rule ids that come back are the reachable set, and every rule
outside it has to be named with a reason. A rule that is neither reachable nor
named fails the test, and so does a rule named as unreachable that has started
firing: Go gaining an FFDHE suite would close that gap, and a gap list still
claiming it is the stale-list failure this document warns about elsewhere.

The rule inventory is read out of the policy package's own source rather than
kept beside it. Cipher rules come from a table and version rules from literals
in a switch, so there is no list to ask for, and a list maintained by hand is
one that goes quietly out of date — which is the thing being guarded against.

Only versions and suites are decided here, and the limit is deliberate.
Certificate rules depend on the certificate a server chooses to present, which
nothing in this repository can enumerate; claiming to have measured that would
be the false completeness this invariant exists to prevent.

*Enforced in:* `internal/tlsprobe.probedVersions`,
`internal/tlsprobe.candidateSuites`, the list in
`internal/tlsprobe/reachable_test.go`
*Guarded by:* `TestEveryGradingRuleIsReachableOrNamed`,
`TestEveryUnreachableRuleIsInTheKnownGaps`

### R16 — One result, two renderers, one set of facts

A scan produces one result and two things render it: `app.js` for a browser
and `cmd/denyfirst-scan` for a terminal. They are different code in different
languages, nothing compared them, and on 2026-08-31 they were answering
different questions. The page carried an Issuance line — which authorities may
issue a certificate for this name, the whole CAA analysis — and the terminal
carried nothing. Not a shorter version of it, and not a note: it was absent,
and had been since the row was added.

The reason it survived is worth more than the defect. A test did guard the
issuance row, and it read the source of `app.js` to check the row was there.
It was there. Nothing asked the other renderer the same question, because
nothing could: everything the terminal printed went to standard output, so no
test could read a line of it. The first test that built a report and read it
found this on its first run.

So the report is now written to a writer, and the two faces are compared by
the questions they answer rather than by the sentences they use. Wrapping and
punctuation may differ; which facts appear may not. A difference that is
deliberate has to be named with what it would take to close it, and a named
difference that has been closed fails the test in the other direction — the
same shape as R15, and for the same reason: a carried gap that is no longer
real reads as though it still is.

Two were named the day this was written, `Revocation` and `Transparency`, and
both are closed. Their sentences were composed in `app.js` and only there,
which put them out of reach of the terminal and out of reach of anything that
could execute them — the revocation sentence went on saying "a status response
was stapled" for a whole policy version after the service had begun parsing
that response, matching it to the certificate, checking its freshness and
verifying the issuer's signature. Writing a second copy in Go would have been
worse than leaving it, so they moved to `internal/policy`, beside the facts
they are made of and the notes written from the same facts, and both faces
read the one string.

The migration was proved rather than asserted. The two composers were lifted
out of the version on `main` and run in a JavaScript engine against every
combination of the facts they read — one hundred of them — beside the Go
functions replacing them, and every sentence matched. The page was then
rendered from a real scan through both versions of `app.js` and compared: the
output is identical. Neither check lives in this repository, because neither
should — a JavaScript engine in CI is a moving part this project does not need
once the sentences are in Go and tested there.

The same reading found a second thing. `Result.Notes` collected notes from the
probe, the certificate, the alternate chains and the stapling, and not from
issuance — so the sentences saying where a CAA answer came from, whether the
resolver claimed it was validated, and why a restriction is not a guarantee
reached a reader of the JSON and no one else. They are collected now.

*Enforced in:* `cmd/denyfirst-scan.printReport`,
`cmd/denyfirst-scan.printCertificate`, `internal/scan.Result.Notes`
*Guarded by:* `TestBothFacesOfTheReportShowTheSameFacts`,
`TestAReportSaysWhatWasMeasured`

### R17 — A finding claims what was measured, not what it implies

`cert.roca` is the sharpest case this project has. Detecting the fingerprint of
Infineon's RSALib costs thirty-eight modular reductions and is close to
certain; factoring a key of that shape costs weeks to months of computation and
this service does not do it, will not do it, and does not need to in order to
have something worth reporting. Between the two sits a temptation, because the
implication is real: a key with that fingerprint can be factored by anybody
willing to spend the time.

The finding says the first thing. *This key carries the fingerprint of a
generator known to produce factorable keys* is what was established; *this key
has been factored* is what was not. The difference costs a reader nothing and
it is the difference between a report that can be checked and one that has to
be believed.

It is also what keeps the finding true if the test is ever wrong. The residue
test is a necessary condition rather than a sufficient one — a modulus with no
relation to RSALib would have to land inside the reachable set modulo all
thirty-eight primes at once, which the published corpora have never seen and
which nothing rules out. A report claiming a factorisation would be false in
that case. A report describing a fingerprint is not.

The same discipline is already elsewhere and is worth naming once: R12 covers
the case where a measurement failed and R3d the case where the path was not
what it seemed. This is the third member of that family — the measurement
succeeded, and the sentence stops where the measurement stopped.

*Enforced in:* the rationale of `cert.roca` in `internal/policy/cert.go`
*Guarded by:* `TestTheFingerprintReachesTheReport`, which requires the finding
to name a fingerprint and refuses one that claims a factorisation

### R19 — A report says how much of the picture it reached, and never more than once

A report described two things: rules that had not been broken, and absences
that had been observed. The strongest sentence it could produce was *Nothing
here fell short of the rules*, which is two negatives, and the prose beside it
listed what a server does not do. On a `strong` result read live, four of five
observations named a shortcoming.

The first answer was a block called **What holds**: nine sentences stating
what the scan had established in the affirmative. It was right about the
problem and wrong about the shape, and reading it on the live site is what
showed why. **Seven of the nine restated something already on the page.** TLS
1.3 accepted and preferred is in the version table. Two transparency
timestamps from two logs is a certificate row, word for word. *The server
imposes its own cipher order* was already printed under the cipher table. A
block that is three-quarters restatement does not earn a screen, and the
reader who learns to scroll past it has also learned to skip the part that was
not a repeat.

What no table says is **how much of the picture the scan reached**, and that
is what a verdict rests on. The cipher table shows four rows whether four was
all of them or whether the host stopped answering after four, and those two
reports mean opposite things: `strong` is the verdict that claims an absence,
and an absence can only be claimed from a complete look.

So one line says what was reached, and it obeys three rules.

**It says only what was reached.** Never what was missed — that belongs once
to the unsettled notes, and a gap named in two places is a gap two sentences
can disagree about.

**It is read from the measurements, never from the findings.** Read off the
findings, *no rule fired* becomes a reassurance, which is what an empty scan
looks like and what a scan looks like when the rule that would have fired is
one nobody has written. A scan that reached nothing says nothing.

**It carries no marks and no colour.** A row of green ticks beside an insecure
verdict reads as approval — kapitalbank.az is graded insecure and every
dimension of it was reached — and a red mark against a name with no CAA record
would be a grade this rule set deliberately does not give (R9). Colour would
put a second opinion on the page beside the first, and two opinions can
disagree.

Beside it, a weak or insecure verdict says what it means. That is the report's
likeliest misreading: a red stamp sits next to a trusted chain, a verified
staple, transparency, CAA and an accepted post-quantum group, and nothing else
on the page says why one option outweighs all of that. `policy.WorstCase` is
one sentence, written once and read by both faces.

**Both are written under the verdict, never in the row with it.** The summary
was one flex row — a column holding the target and the address, the stamp
beside it — and this line was added to that column as a `dl`. A `dl` is a
block, so the column took the whole width and the stamp wrapped to a line of
its own. On a live report the reader met the hostname, then *Worst case: an
attacker chooses which option to negotiate…*, then four lines of coverage, and
only then the word INSECURE: the explanation of a verdict arriving before the
verdict, and the one element the page exists to deliver last in its own block.
Nothing was false and nothing failed. It rendered, and it read backwards,
which is why it survived a release — and why the rule is now about position
and not only about wording.

The tests over `Coverage` run every combination of what a scan can reach —
thirty-two of them — because the first version of them ran one live scan,
that scan had no transparency and no CAA, and it therefore never saw two of
the five clauses it claimed to check. A sabotage that put the word *no* into
one of those clauses went straight past it.

*Enforced in:* `internal/policy/coverage.go`,
`internal/scan.coverageFacts`, `internal/web/assets/app.js`,
`internal/web/assets/style.css`
*Guarded by:* `TestCoverageNamesNothingItDidNotReach`,
`TestCoverageIsEmptyWhenNothingWasReached`,
`TestEachClauseWaitsForWhatItDescribes`,
`TestCoverageIsOneSentence`,
`TestTheCoverageLineSaysWhatWasReached`,
`TestAScanThatReachedNothingClaimsNoCoverage`,
`TestAWeakOrInsecureVerdictSaysWhatItMeans`,
`TestBothFacesSayWhatAVerdictMeansInTheSameWords`,
`TestTheVerdictIsGivenBeforeItIsExplained`,
`TestTheVerdictRowIsSeparateFromWhatIsWrittenUnderIt`

### R18 — A note carries the kind of claim it makes

A report says three different things that are not verdicts, and for as long as
this project has existed it said all three under one heading.

The heading was *What this did not measure*. Under it went every sentence that
was not a finding: what the scan established and chose not to grade, what it
could not settle about this host, and what this program never claims about any
host. A scan of kapitalbank.az on 2026-09-01 produced eleven of them. Three
were limits of that scan. The rest were a post-quantum key exchange that had
been measured and had passed, a stapled revocation response that had been read
and verified, a CAA restriction that had been found, five transparency
receipts that had been counted, and the standing properties of the instrument.

Nothing in that list was false. The heading was, for eight of the eleven, and
a reader takes the heading — so a report that establishes a great deal read as
a report that had established almost nothing. Being wrong about the frame is
not a smaller fault than being wrong about the fact; it is the same fault at
the point where the reader actually meets it.

Every note now carries one of three kinds, and the kind is chosen where the
sentence is written, by the code that knows which it is:

| Kind | What it claims | Where it appears |
|---|---|---|
| `observed` | Established by this scan, deliberately not graded | Under **Observed**, open by default |
| `unsettled` | This scan could not settle it, and the reason lies with this host | Under **Not established for this host** |
| `standing` | True of every scan this program runs | Not on the report. Counted, and linked to `/method` |

The third is not printed. A limit that is the same on every report is one
nobody reads by the third report, and sitting beside a host's own
shortcomings it reads as though it were one of them. The four are declared
once in `internal/policy/standing.go`; `/method` ranges over that declaration
and `denyfirst-scan -limits` prints it, so the page cannot fall out of step
with the code and somebody offline is not sent to a website.

Moving them is only honest if the report still says they exist. It gives the
count and names both places to read them, and a test fails if it stops doing
either — or if a standing sentence is written inline rather than added to the
declaration, which would leave a report claiming four limits while carrying a
fifth that nothing explains.

Classifying afterwards by reading the finished prose was the alternative and is
rejected for the reason R12 gives: it puts the sentence and its label in two
places, and two places drift. There is no way to append a note without naming
its kind — the packages expose `observe`, `unsettled` and `standing`, and
nothing writes to the list directly.

Both faces of the report take the sections, their order and their words from
one declaration each, and a test reads both sources and compares them. A
section renamed on the page and not in the terminal fails; a section on one
face and not the other fails.

*Enforced in:* `internal/policy/note.go`, `internal/policy/standing.go`;
`noteSections` in `cmd/denyfirst-scan`; `NOTE_SECTIONS` in
`internal/web/assets/app.js`; `assets/method.html`
*Guarded by:* `TestEveryNoteInAReportCarriesAKind`,
`TestBothFacesNameTheSameNoteSections`,
`TestLimitsOpenOnlyWhenTheyAreTheWholeReport`,
`TestTheStandingLimitsAreNamedAndLinked`,
`TestTheReportPointsAtTheLimitsItDoesNotPrint`

### R9a — A CAA value is an authority and its parameters, not one string

RFC 8659 §4.2 puts parameters after the authority inside a single value:
`pki.goog; cansignhttpexchanges=yes` names one authority and sets one
parameter. The whole value used to go into the list unchanged, and the list is
joined with commas while the clauses around it are joined with semicolons — so
a real record set rendered as

> issuance limited to comodoca.com, digicert.com; cansignhttpexchanges=yes,
> letsencrypt.org, pki.goog; cansignhttpexchanges=yes and ssl.com

which a reader cannot parse, and which invites reading
`cansignhttpexchanges=yes` as an authority of its own. Measured on
kapitalbank.az, 2026-08-23, from a live report.

The parameter is shown rather than dropped. `cansignhttpexchanges` authorises
that authority to sign Signed HTTP Exchanges, which is a wider power than
issuing an ordinary certificate, and a reader judging whether a zone's
restrictions are tight enough needs to see it. An empty value permits nobody
and is named rather than allowed to vanish from a list.

This is the third instance of one pattern in as many days: the packages
computed the right answer and the sentence built from it said something else.
It was found by reading a live report, which no test in this repository does.

*Enforced in:* `internal/policy.readable`, applied by
`internal/policy.describeAuthorities`
*Guarded by:* `TestCAAParametersAreNotMistakenForAuthorities`,
`TestAuthoritiesWithoutParametersAreUnchanged`

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

There is a second half this cannot fix, and it is said instead. A subject
spelling a familiar name with a Cyrillic `\u0430` where a Latin `a` belongs is
not hiding anything: the two are different characters that render identically,
and folding one into the other would corrupt every legitimate name written in
those scripts. So nothing is rewritten, and a note says when a name draws on
more than one of the three alphabets whose letters are routinely mistaken for
each other.

Each value is examined on its own rather than the printed distinguished name.
`CN=` is Latin whatever follows it, so a check over the printed form would
find two alphabets in every certificate ever issued to a Cyrillic or Greek
name and tell most of the world that its own alphabet looks like a forgery.
One script throughout is a language, not a disguise.

The verdict is untouched. A company with a Cyrillic name and a Latin domain
suffix is an ordinary customer of an ordinary authority, and grading that down
would be this project inventing a fault.

*Enforced in:* `internal/certinfo.sanitise`, applied by `trimmer.text`;
`internal/certinfo.mixedScriptNote`, `internal/certinfo.confusableScripts`
*Guarded by:* `TestControlCharactersInCertificateFieldsAreNeutralised`,
`TestC1ControlsAreNeutralisedToo`, `TestTrimmingCutsOnARuneBoundary`,
`TestNothingCanRewriteHowTheReportReads`, `TestANameInTwoAlphabetsIsSaid`,
`TestALookalikeNameIsNotRewritten`

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

Comparing the copies was, until 2026-08-22, the whole of the check, and it
never looked at the key. A key file swapped for another, leaving both
published fingerprints alone, passed everything in this repository — which is
precisely the attack the fingerprint exists to stop, since the reporter
compares the two numbers and then encrypts to whatever was actually served.
The fingerprint is now computed from the bytes this server sends: the armour's
own checksum is verified, the first packet is required to be a public key, and
its version 4 fingerprint is SHA-1 over `0x99`, the packet length and the
packet body. Sixty lines of standard library, no dependency, and the gap that
said it needed "an OpenPGP parser" needed the first packet of one.

The key certifies and encrypts and does nothing else, and is unrelated to the
release signing key, which is an SSH key pointing outward rather than in.

`security.txt` is not signed. A clearsigned file would be verified with the
key it points at, which answers nothing a forger could not arrange.

*Enforced in:* `internal/web`, the route table and `assets/security.txt`
*Guarded by:* `TestSecurityTxtIsServedAtTheWellKnownPath`,
`TestLegacySecurityTxtPathRedirects`, `TestSecurityTxtHasTheRequiredFields`,
`TestSecurityTxtExpiryIsMovedByAPerson`,
`TestSecurityTxtDoesNotSendExclusionRequestsToSecurity`,
`TestFingerprintAgreesAcrossSources`, `TestTheServedKeyIsTheKeyWePublish`,
`TestTheServedPacketIsAPublicKeyPacket`

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

The job in CI runs on pushes and pull requests, which is not the same claim.
`govulncheck` answers from a database, and its answer changes when Go
publishes a security release without a line of this repository changing — so a
commit that was clean when it merged can be tagged weeks later and shipped
carrying a known reachable vulnerability, with every check on the page still
green. The release workflow therefore runs it again, against the tagged
source, before anything is staged.

*Guarded by:* the `Known vulnerabilities` job in CI, and the
`Refuse to stage a build with a known vulnerability` step in
`build-release.yml`

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

### S8 — A release is built only from source that passes its own gates

A tag can be put on any commit. CI runs on pushes and pull requests, so the
default branch is green; nothing checked that the commit being released was
one of those. A tag placed on an older commit, on an unmerged branch, or on
anything reachable by whoever holds the token produced a draft release with no
gate in front of it at all — and the human step that follows is *check the
hashes*, which confirms that the bytes are the bytes and says nothing about
whether they work.

`build-release.yml` now runs `go vet`, `go test ./...` and `govulncheck`
against the tagged source before staging the draft.

They run **after** the build rather than before it. Nothing a gate installs or
compiles can then have influenced the bytes that were produced, so the
reproduction still compares like with like — which matters more here than the
few seconds saved by failing early.

*Enforced in:* `.github/workflows/build-release.yml`, the two `Refuse to
stage` steps

### S9 — A published release is checked, in public, for a signature

*Nothing reaches a user unsigned* was a procedure and not a property.

The signature is made on the maintainer's machine and uploaded by hand, which
is the arrangement that keeps the key out of GitHub and is worth keeping. What
it means is that publishing is one button and signing is several steps before
it, in a different place — so a draft published a step early, or published by
somebody who took the account, reaches every user with no signature and
nothing anywhere says so. The one person who would notice is the person who
just failed to sign it.

`reproduce.yml` runs on publication. It now downloads `SHA256SUMS.sig` and
verifies it with `ssh-keygen -Y verify` against `.allowed_signers` before it
rebuilds anything, and the result is a public red mark on a public log.

It then requires the tag's `.allowed_signers` to be byte-identical to the
default branch's. Either copy can be moved by anyone who can write here, so
neither is a root of trust; what is worth catching is the two disagreeing,
because `docs/verify.md` sends a reader to the default branch's copy while the
signature was checked against the tag's.

*Enforced in:* `.github/workflows/reproduce.yml`, the
`Check that the release is actually signed` and
`Check that the tag trusts the same keys` steps

### S10 — A binary can say which release it is

`-buildvcs=false` is deliberate: the embedded VCS stamp varies with how the
tree was fetched, so leaving it on makes two honest builds of one tag differ
and destroys the property S3 and the reproduction workflow exist to establish.
The consequence was that nothing inside a released binary said what it was.
The tag is in the filename, and a filename survives until somebody renames the
file, packages it, or copies it onto a server as `denyfirst-scan`.

For a program people run to answer security questions, *am I running the build
that fixed this* is not a cosmetic question, and it had no answer.

`scripts/build.sh` links the tag in with `-X main.version`. Both commands
print it beside the policy version, which answers a different question — the
build, and the rules it grades by. A binary built any other way says so rather
than guessing.

Determinism is unaffected: the value is the tag, both callers pass the same
one, and two builds of a tag remain byte-identical. Measured on 2026-08-22,
twice, all ten artifacts.

*Enforced in:* `scripts/build.sh`, `cmd/denyfirst-scan.version`,
`cmd/denyfirstd.version`
*Guarded by:* `TestTheBuildScriptStampsTheVersionSymbolThisProgramDefines`,
`TestAnUnstampedBinaryDoesNotClaimAVersion`,
`TestThePolicyVersionIsNotTheReleaseVersion`

### S11 — A rule set that changes says what changed

Verdicts carry the name of the rule set that produced them (R1) precisely so
that two reports can be compared. That only helps if a reader can find out
what moved: a server graded `strong` under `denyfirst-v1` and `weak` under
`denyfirst-v2` may not have changed at all, and a pipeline that reads the
output needs to tell a configuration that got worse from a rule that got
stricter.

`docs/policy-changes.md` is that record. Bumping `policy.Version` without
adding to it fails a test, and naming a rule identifier that does not exist
fails another — the same rule as the invariant citations here, for the same
reason: a page naming things nobody can find is a page nobody can check.

The record also has to say **which release** moved the rule set, because that
is the first thing a reader comparing two reports needs: which upgrade to
distrust. A section is written before the release that carries it exists, so
it says "Unreleased" until somebody returns to it, and on 2026-09-01 nobody
had — `denyfirst-v4` was still marked unreleased five releases and three weeks
after v0.4.0 shipped it. So a rule set that is no longer the one in force must
name its release, and the procedure stops on the word before a tag is cut.

*Enforced in:* `docs/policy-changes.md`, `docs/releasing.md`
*Guarded by:* `TestTheChangeLogCoversTheCurrentPolicy`,
`TestTheChangeLogNamesRulesThatExist`,
`TestEveryRuleSetThatShippedNamesItsRelease`

### S12 — A tag cannot be moved or deleted

A signature over a tag is a statement about which commit was released. If the
tag can be moved, the statement expires the moment somebody moves it: the
hashes people verified against stay valid, the signature still checks out, and
the tag now names something else. If it can be deleted, a release can be
withdrawn from the record rather than superseded in it.

Both restrictions are on. They are a repository ruleset rather than anything a
checkout can assert, which is why they are written here beside S6's merge
settings, and this is the first thing to look at if a signature ever appears to
cover the wrong source.

The cost is real and worth naming: a dry run leaves a signed tag behind for
ever. `gh release delete --cleanup-tag` fails on the second half, correctly,
and the recovery is to delete the draft release and leave the tag — which is
why release candidates carry `-rcN` rather than reusing the number that will
ship. Measured on 2026-08-22, on `v0.2.0-rc1`, which is still there.

*Enforced in:* the repository's tag ruleset — restrict deletions and restrict
updates, both on
*Guarded by:* nothing a test can reach. `docs/releasing.md` records it as a
prerequisite so that a procedure depending on it says so.

### S13 — The release procedure is written down, and its first instruction works

Every property above depends on somebody carrying out a sequence of steps in
order, on one machine, a few times a year. Until 2026-08-22 that sequence
existed in a chat window and nowhere in this repository — so the one procedure
that decides what people download was the one procedure a reader could not
check, and a maintainer who lost the window would have had to reconstruct it
from three workflow files and a PowerShell script.

`docs/releasing.md` is that sequence, including the dry run, what each step
establishes, and the two repository settings it rests on.

The first instruction has to work, which is not a detail. `release.ps1`'s own
example was `.\scripts\release.ps1 -Tag v0.1.0`, and on a default Windows
installation PowerShell refuses to run a script file at all — so the release
procedure's entry point was a documented command that fails before the script
starts, on the single kind of machine it exists to run on. This is the same
class of defect as the `-X main.version` recipe in `docs/verify.md`: a document
naming a command nobody had run. The example now names the invocation that
works, and says why not to fix it by relaxing the machine's policy — the
execution policy is not a security boundary, so making it permanent buys
nothing and loses the accident it does prevent.

The same reasoning reaches every command in it, not only the first. A
procedure is a set of instructions, and an instruction that opens a menu is
one somebody answers wrongly at two in the morning: `gh run watch` with no run
named lists every recent run and waits, and on 2026-08-23 the CI run was
chosen instead of the build, the draft release was taken to exist, and the
next command answered `release not found`. Every run command in these pages
now names the run it acts on.

The page also carries what happens before a release, because that is where the
release goes wrong. Four pull requests were left green and unmerged in one
day, and one of them was the only reason v0.3.1 existed — so the tag was cut,
signed, reproduced and deployed without the fix it was for. A commit is also
now looked at twice, before staging and after, which is what would have kept
two saved workflow logs out of `main` on 2026-08-31.

*Enforced in:* `docs/releasing.md`, `scripts/release.ps1`'s help
*Guarded by:* `TestTheReleaseProcedureIsWrittenDown`,
`TestTheDocumentedInvocationIsTheOneThatWorks`,
`TestEveryRunCommandNamesItsRun`

### S14 — A gate goes red for its own subject, and for nothing else

The nightly fuzz run is the only check here that can find something nobody
thought to look for. Every other check asserts a property somebody already knew
to write down; this one searches. That makes its red mark the most valuable one
in the repository, and makes it the check least able to survive being ignored.

On 2026-08-27 it went red for a reason that had nothing to do with this code.
`go test -fuzz` installs the `-fuzztime` budget as a context deadline on its
coordinator, and on the way out the coordinator means to swallow that deadline:
it compares the error it is holding against the workers' context error with
`==`, which is a comparison between two different contexts' errors made on a
shutdown path with several goroutines on it. When it does not hold, a run that
found nothing ends by reporting `context deadline exceeded` as a test failure.

Nothing was found, and that is established rather than assumed. Executions were
still climbing at twenty-six thousand a second at the moment the budget
expired, so no worker was stuck on an input. No file was written under
`testdata/fuzz`. And `go` prints `Failing input written to` for every error
that carries a crash, so an error printed without that line carries none.

The mark then went unread for five days and was noticed by accident. That is
the predictable outcome, and it is the reason this is an invariant rather than
a one-off fix: a gate that can go red for a reason other than its own subject
trains whoever watches it to skip it, and they will skip it on the night it
means something. One target-run in the fifty-five on the last five nights is
thin evidence for a rate, but it is not thin evidence that the problem exists.

So the step classifies its result rather than propagating it. A written
reproducer is looked for first, so a run that both found an input and tripped
the deadline is still reported as a finding. Then exactly one shape is allowed
through, and every part of it is required: one failing target, the
coordinator's deadline as the whole of the message, a duration that reached the
budget, none of the lines the toolchain prints when something real went wrong,
and a re-run of the seed corpus — with no deadline anywhere in the picture —
that comes back clean. Everything else fails, including anything the step does
not recognise.

The risk of classifying is that a real failure is filed as noise, and it is
worth naming rather than waving away. Three things hold it down: the shape is
narrow, the step fails closed on anything outside it, and the discriminator is
the toolchain's own crash reporting rather than a guess about what a crash
looks like.

The same edit closes a second gap the incident exposed. A reproducer was only
ever printed into the job log, and a job log expires after ninety days — so the
one artefact that turns a random discovery into a permanent regression test was
kept in the most perishable place in the system, and this one came within days
of being lost. It now goes to the job summary and an annotation as well as the
log. Nothing uploads an artifact, because no third-party action runs here (S1),
and that constraint is not one to work around.

*Enforced in:* `.github/workflows/fuzz.yml`, the classification in the fuzz
step
*Guarded by:* nothing a test can reach — the shape it recognises is produced by
a race inside the toolchain's own shutdown path and cannot be provoked on
demand. The step fails closed instead, which is the property a test would have
been asserting.

### S15 — The deploy is a step with a procedure, not the end of one

Everything S1 to S14 establishes is about bytes in a release. A user reaches a
running process, and the claim that the two are the same thing is made by a
person typing commands into a server a few times a year.

That sequence was written nowhere until 2026-09-01. `docs/releasing.md` said
*then deploy* and gave one command — `denyfirstd -version` — which is not on
`PATH` on the machine it was written for, so the single instruction that
existed failed on the evening it was first followed. This is the defect S13
records about the release procedure's entry point, in the one procedure S13
did not cover.

What the procedure now establishes, in order. The release was reproduced
before it was installed, because a signature and a public build without a
reproduction say only that one laptop's output is self-consistent. The
signature is checked again on the server rather than only on the laptop that
downloaded it, against a key fetched from the repository rather than from the
release beside it — a signature verifies against whatever key it is handed.
The file is installed with owner and mode set as it is written and moved into
place by a rename, so there is no interval in which the live path holds a file
that is half-written or owned by the wrong account. The service runs as
`denyfirst` and the file is `root:root`, so the account that executes it
cannot rewrite it. The binary carries no file capability: the unit grants
`CAP_NET_BIND_SERVICE` to one process at start, which is a smaller claim than
granting it to anybody on the machine who runs the file.

And the running process is identified through `/proc/<pid>/exe` rather than by
running the file on disk. `-version` reports what was installed; a restart
that failed leaves the previous process alive on the previous inode, still
answering, with the new file in place and looking correct. Those two states
are indistinguishable from the file, which is the reason the check is not the
obvious one.

The rollback is kept under the version it holds. `denyfirstd.bak`, left on
this server on 2026-08-18 with nothing recording what was in it, is what the
alternative looks like a week later.

*Enforced in:* `docs/releasing.md`
*Guarded by:* `TestTheDeployProcedureIsWrittenDown`,
`TestTheServiceIsNamedByThePathItIsAt`

## Known gaps

Listed rather than hidden. An unnamed gap is a surprise; a named one is work.

A stale list is worse than no list, because a reader takes it as current. Four
entries were removed when this was last read: the server binary, the pinned CI
tools, release signing, and fuzzing all exist now. Two more went at the review
after that: P1 has a test, and the flag that could not take effect was removed
rather than fixed. One more went with "no independent review", because that
review has happened; what it found is written into the rules above rather than
summarised here — A6 to A9, R10, S3 to S5, W1 and W2 all exist, or say what
they now say, because of it.

One more goes on 2026-08-22, and it had already been fixed. Unnamed extended
key usages were closed in `internal/certinfo` that morning and stayed on this
list until the afternoon, which is this document doing, on its own front page,
the thing it warns about — the entry now has a test rather than a paragraph.
The reason it lingered is worth keeping in mind for the entries below: a gap
closed in code is not closed on this page until somebody comes back for the
page.

Four more go the same day, and these were closed on purpose rather than found
already closed. The published key is now verified from the bytes the server
sends (D1). A chain a server serves only to old clients is now graded, and the
worse of the two sets the verdict (R14). An address family that could not be
reached is now named, so a limit of this scanner's network is no longer
reported as a fault of the server (R3d). And a name written in two alphabets
now raises a note, which is the most a report can do about a pair of letters
that are genuinely different characters rendering identically (R10).

Each of those was on this list with a sentence explaining why it was hard. Two
of the four sentences were wrong: "needs an OpenPGP parser and SHA-1" needed
the first packet of one, and the address-family entry described a budget
problem that `interleaveFamilies` had already solved, leaving only the missing
sentence. A reason written when an entry is added is worth re-reading before
it is believed.

Anything below is open today.

- **Transparency receipts are counted and not verified.** R3c. Checking one
  needs the issuing log's public key, and the qualified-log list is maintained
  by browsers on their own schedule.
- **A stapled response's responder is not itself checked for revocation.**
  R3b. The response is now parsed and verified; what remains is the responder
  certificate's own status, and checking it means fetching a second response
  over the network from an address the scanned party chooses. This scanner
  fetches nothing. RFC 6960 lets an issuer waive the check and responder
  certificates are short-lived for the same reason, so this is a residual
  rather than a hole — but it is a residual, and a compromised responder key
  would not be caught here.
- **No real responder's bytes are in the test corpus.** Every OCSP response
  the tests read was built by the tests. What that used to mean was worse than
  it sounds: the built responses all had one shape — name-form responder
  identifier, SHA-1 CertID, ECDSA signature, one entry, no extensions, an
  omitted version — and a real authority varies every one of those. Nine
  variants are now exercised, together and separately, including a key-form
  responder identifier, a SHA-256 CertID, an RSA signature from a delegate, a
  nonce, an archive cutoff, an absent `nextUpdate`, an explicit version and
  three entries with ours last. They are also fuzz seeds.

  What remains is that no authority's actual bytes have been through it. The
  failure that would cause is the one this project minds most: a
  `cert.staple-unverifiable` finding, which is `Weak`, raised against a server
  doing everything correctly — a false accusation, which a reader cannot tell
  from a real finding. Capture the first response a live scan verifies and
  commit it as a fixture.

  *Closed 2026-08-23.* Measured from a host with unintercepted egress: of
  fourteen well-known sites, five staple — DigiCert, Sectigo, Apple, Microsoft
  and PayPal — and nine, including GitHub, Cloudflare and Mozilla, send
  nothing. All five verified on the first attempt, across four encoders,
  response sizes from 471 to 2341 bytes, and both signing arrangements. The
  bytes are in `internal/ocsp/testdata` with the moment to judge each at,
  because a real response expires within days and a test that goes red on a
  Tuesday teaches people to ignore it.

  It could not be closed from the author's own machine, and the reason is
  worth keeping. Every outbound TLS connection there is intercepted and
  re-presented by a gateway that staples nothing, so twenty-one hosts each
  appeared to staple nothing — a confident measurement of the path rather than
  of the servers, which is precisely the error R3d exists to name. The tell
  was that every one of them showed a chain of exactly three certificates.

  What the measurement also settles: this check reaches about a third of
  hosts. A revoked certificate on a server that does not staple is invisible
  here, and `revoked.badssl.com` — a host that exists to serve one — is among
  the nine. Each report says so on its own Revocation line rather than leaving
  it to be inferred.
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
  reading, not a funded engagement. As of 2026-08-22 that reading has covered
  every file in the tree: `internal/policy` and `internal/certinfo`, which were
  its thinnest ground and held the errors that mattered most — a prohibited
  suite graded strong, a verdict whose stated reason was false, a certificate
  reported trusted because Go stopped checking at the dates — then
  `internal/tlsprobe`, `internal/dnsclient` in full including the reply parser,
  `internal/safedial`, `internal/httpapi`, `internal/scan`, `internal/web`, and
  finally the two front ends, `internal/web/assets/app.js` and
  `cmd/denyfirst-scan`, which had never been read and held R12 and R13 between
  them, and `cmd/denyfirstd`. That last fact is the one to take from this entry rather than the
  coverage: the packages that compute the answer were careful, and every defect
  found on the final pass was in the code that shows it. Nothing was wrong with
  what this project knew; four things were wrong with what it said. Completing
  a reading is not the same as having been audited, and one reader who wrote
  the code is the least independent reader available.
- **A refused version and a version with no suite in common look identical.**
  Both answer with a handshake failure alert, so a server configured only for
  suites Go does not implement is reported as refusing every version it in fact
  speaks. R12 puts the sentence saying so into any report containing a refusal,
  which is the honest half; the row itself still reads `refused`, because from
  outside there is nothing else it could say. Closing it would need a TLS
  client that can offer suites Go does not implement, which is the same
  requirement as the entry below.
- **Eleven grading rules cannot fire through this front end.** Measured rather
  than estimated: every version in `probedVersions` and every suite in
  `candidateSuites` is graded, and the rules that never come back are these.
  Nine of the thirteen cipher rules and two of the three version rules are in
  this position, and until 2026-08-31 one of them was named here and the other
  ten were not.

  The cause is the same in almost every case. This scanner speaks through Go's
  TLS client, so it can only offer what Go implements, and a rule that matches
  a suite Go does not implement will never be shown one. `cipher.null`,
  `cipher.no-encryption` (RFC 9150 integrity-only), `cipher.anonymous`,
  `cipher.export`, `cipher.des` — single DES, not the 3DES rule beside it,
  which is reachable — and `cipher.md5` are all of that kind.

  `cipher.ffdhe` is the one worth reading twice, because it changes what a
  report means: Go offers no finite-field DHE suite, so a TLS 1.2 server
  configured for DHE alone is measured as accepting nothing, and the report
  does not distinguish that from a server that refused everything for its own
  reasons.

  `version.ssl3` has the same shape and the same consequence. Go removed
  SSL 3.0 in 1.14, so a server speaking only SSL 3.0 is reported as refusing
  every version rather than as insecure. After POODLE such a server is close
  to extinct, which is a reason it matters little and not a reason it is
  untrue. `version.unknown` cannot fire because `probedVersions` is a fixed
  list, and `cipher.unrecognised` cannot fire because an enumeration that only
  offers suites this Go names cannot be answered with one it does not.

  `cipher.not-current-practice` is different and is listed for honesty rather
  than for the same reason. It is the catch-all that grades a suite matching no
  specific rule, and it is reachable in principle; for all twenty-two suites
  this prober can offer, a more specific rule matches first and stops the
  search. It is shadowed rather than impossible.

  None of this makes the rules wrong. They are correct and they are not
  coverage, and the second half is what a reader deciding whether this report
  is enough needs to be told. R15 keeps the list from drifting in either
  direction — a rule that quietly stops firing, and a gap still claimed after
  Go closes it.

- **A lookalike alphabet is reported, not resolved.** R10 raises a note when a
  name draws on more than one of Latin, Cyrillic and Greek, which is as far as
  a report can honestly go: the characters are genuinely different and folding
  them together would corrupt every legitimate name in those scripts. What the
  note cannot do is tell a disguise from a company whose name really is
  written in two alphabets, and it says nothing at all about a name spelled
  wholly in one script that resembles a name in another — `рaypal` in Cyrillic
  throughout raises nothing, because one script is a language. Hostname
  matching is unaffected either way; it compares bytes.
- **Four commits on `main` carry no signature.** S6. `1fdf674`, `cc163a3`,
  `01fc49f`, `7cd2cfa` — rebase-merged, which strips the signature the author
  put on them. The signed originals are the tag
  `signed/2026-08-20-docs-and-build` and the trees are identical, so the
  provenance exists; it is one `git diff` away rather than in the log, which is
  not the same thing. Closing it needs a force-push to `main`, and opening that
  door costs more than the four commits are worth.
- **The prose pages drift, and only some sentences have a test behind them.**
  The privacy page and the README each carried a claim that stopped being true
  the day OCSP validation landed — *revocation is not checked* — and the
  privacy page stated the per-target threshold twice, as eight in one section
  and twice in another, with a test guarding only the first. Both are fixed and
  both now have a test. What remains is the general case: these pages make
  claims in prose, a test can only check the sentences somebody thought to
  pin, and every rule added to `internal/policy` is a chance for one of them to
  go quietly wrong. Re-read them whenever a policy version changes.