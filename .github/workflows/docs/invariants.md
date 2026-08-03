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

The hostname is resolved once and the resolved literal is dialled, so a name
that answers differently on a second lookup cannot redirect the connection
after it was checked.

*Enforced in:* `internal/safedial`, by default in `safedial.Dialer`
*Reached through:* `tlsprobe.Prober.dial`, which selects safedial when
`Dial` is nil
*Guarded by:* `TestCheckAddrBlocks`, `TestDefaultDialerRefusesPrivateTargets`,
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

---

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
*Guarded by:* review — **no test asserts the notes are present**, which is a gap

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

- **P1 and R3 have no tests.** Both are enforced by review, which is the
  weakest form of enforcement this document argues against.
- **No server binary exists yet.** `httpapi.Server` is an `http.Handler` with
  nothing listening. The timeouts that matter against Slowloris —
  `ReadHeaderTimeout` in particular — live on `http.Server` and are therefore
  not yet set anywhere.
- **CI installs its tools with `@latest`.** The Go module proxy verifies each
  download against the checksum database, which is stronger than a git tag,
  but the version is still whatever exists on the day.
- **Release artifacts are not signed.** Nothing lets a user verify that a
  binary came from a particular commit.
- **No fuzzing.** The certificate and target parsers take untrusted input and
  have only example-based tests.
- **No independent review.** Nobody outside this project has read the code.