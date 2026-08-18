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
offset, 6to4 and NAT64 at two more. Each family needs a prefix of its own, and
`2001::/23` covers several at once because IANA reserved that block for
exactly this kind of assignment.

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
`TestForwardedHeaderReadFromTheRight`

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

*Enforced in:* `internal/httpapi.limiter.makeRoomLocked`,
`internal/httpapi.clientKey`
*Guarded by:* `TestFullLimiterStillAdmitsNewClients`,
`TestForgedForwardedForCannotMakeNewKeys`

---

## Privacy

### P1 — Nothing about a request is recorded

Not the target, not the client address, not the result. Addresses held for
rate limiting live in memory and are swept as they go idle.

This includes the parts nobody wrote. Go's `http.Server` logs lines such as
`http: panic serving 203.0.113.7` to standard error by default, so the server
must be given a discarding logger. A promise that depends on a library's
default staying convenient is not a promise.

*Enforced by:* the absence of logging in `internal/httpapi`, and
`httpapi.SilentErrorLog` passed to `http.Server.ErrorLog`
*Guarded by:* review — **there is no test for this yet**, which is a gap

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

### R2 — Every verdict cites a document

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
`TestZeroTimestampCountIsExplained`

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

*Enforced in:* `internal/certinfo.embeddedSCTs` for the count,
`internal/policy.DescribeTransparency` for what it means, joined in
`internal/scan.Scan`
*Guarded by:* `TestParseSCTListCountsTimestampsAndLogs`,
`TestParseSCTListRefusesMalformedInput`, `FuzzParseSCTList`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestLoggedNoteDoesNotClaimTheReceiptsWereVerified`,
`TestBothCountsAreReported`, `TestTransparencyReachesThePage`

### R4 — Nothing measured is not the same as passing

An unreachable server is ungraded, not strong.

*Enforced in:* `internal/policy.Ungraded` and `policy.Worst`
*Guarded by:* `TestNothingMeasuredIsUngraded`, `TestUnreachableTargetIsUngraded`

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

---

## Known gaps

Listed rather than hidden. An unnamed gap is a surprise; a named one is work.

A stale list is worse than no list, because a reader takes it as current. Four
entries were removed when this was last read: the server binary, the pinned CI
tools, release signing, and fuzzing all exist now. Anything below is open
today.

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
- **`-trusted-proxy-hops` is a flag that cannot take effect.** `TrustedProxies`
  is never populated from the command line, so `withDefaults` silently returns
  the hop count to zero. It fails safe and it misleads: an operator who sets it
  believes X-Forwarded-For is being read and it is not.
- **An address family that cannot be reached is not named.** The dialler
  resolves both families and tries up to eight addresses. On a host with IPv6
  disabled, a target with many AAAA records can spend that budget on
  unreachable addresses and be reported as unreachable, with no note saying
  why. R3 requires the opposite.
- **P1 has no test.** Enforced by review, which is the weakest form of
  enforcement this document argues against.
- **No independent review.** Nobody outside this project has read the code.