# What changed between policy versions

Every verdict this project produces carries the name of the rule set that
produced it, and reports from two different rule sets are not comparable. A
server graded `strong` under `denyfirst-v1` and `weak` under `denyfirst-v2`
may not have changed at all.

This page says what moved, so that anyone whose pipeline reads the output can
tell a configuration that got worse from a rule that got stricter.

The rule identifiers are stable across releases. A finding can be tracked or
suppressed by its identifier rather than by matching prose, and the prose is
free to improve without breaking that.

---

## `denyfirst-v2` → `denyfirst-v3`

Released in v0.3.0, 2026-08. One change, and it is the largest single change
this project has made to what a report means.

### The stapled response is now read

Until now this project observed that bytes arrived in the handshake and said
*a certificate status response was stapled*. It never parsed one. A server can
staple anything — an empty file, a year-old response, a response about a
different certificate, one signed by nobody, or one that says revoked — and
all of them produced the same sentence, which a reader takes to mean
revocation was checked.

The response is now parsed and has to pass every one of these before its
status is reported: the responder answered successfully with a basic response;
the entry describes **this** certificate by issuer name hash, issuer key hash
and serial number, all three; it was produced in the past and has not expired;
and it is signed by the issuer, or by a responder the issuer both signed and
marked with the OCSP-signing extended key usage.

| Rule | Verdict | When |
|---|---|---|
| `cert.revoked` | Insecure | A verified response says the certificate was withdrawn |
| `cert.revocation-unknown` | Weak | A verified response says the authority has no record of this serial. Not the same as *not revoked* |
| `cert.staple-unverifiable` | Weak | Bytes were stapled and establish nothing: malformed, expired, about another certificate, or unsigned |

`cert.must-staple-not-stapled` changed meaning. It fired only when no response
arrived, so a certificate demanding a staple and receiving sixteen bytes of
rubbish passed it. It now fires unless a response arrives **and verifies**,
which is what a client honouring RFC 7633 requires — for such a client an
unverifiable response and an absent one are the same outcome: the handshake
fails.

Two things deliberately did **not** change. A missing staple is still not
graded, for the reason at the top of `internal/policy/staple.go`: the
authority decides whether a response exists, and several no longer publish
OCSP at all. And a chain that omits the issuer produces no finding here —
nothing can be verified without it, `cert.chain-incomplete` already grades the
omission, and charging one mistake twice would report it as two.

### What is still not checked

The responder certificate's own revocation status. Checking it means fetching
another response over the network from an address the scanned party chooses,
and this scanner fetches nothing: it reads only bytes the server already sent.
RFC 6960 §4.2.2.2.1 lets an issuer waive the check, and responder certificates
are short-lived for the same reason.

---

## `denyfirst-v1` → `denyfirst-v2`

Released in v0.2.0, 2026-08.

### Suites that now grade worse

| Rule | Was | Is | Why |
|---|---|---|---|
| `cipher.ffdhe` | *(no rule)* | Insecure | RFC 10015, July 2026, updates BCP 195: ephemeral finite-field Diffie-Hellman moved from SHOULD NOT to **MUST NOT** for (D)TLS 1.2. Static RSA and non-ephemeral FFDH moved with it. |
| `cipher.no-forward-secrecy` | *(no rule)* | Insecure | Static RSA, static DH and static ECDH key exchange. A recorded session is decrypted by anyone who later obtains the server's key. |
| `cipher.no-encryption` | *(no rule)* | Insecure | RFC 9150's `TLS_SHA256_SHA256` and `TLS_SHA384_SHA384` authenticate and do not encrypt. Graded `strong` before, because nothing in the rules had considered a suite with no cipher in it. |
| `cipher.unrecognised` | Strong | Weak | A suite whose key exchange this project cannot identify was graded as though it had passed. An unreadable answer is not a pass. |
| `cert.signature-algorithm-unrecognised` | Strong | Weak | The same rule for a signature algorithm with no name. |
| `cert.key-algorithm-unrecognised` | Strong | Weak | The same rule for a key algorithm with no name. The algorithm is named in the finding. |

### Verdicts that are now withheld rather than given

| Situation | Was | Is |
|---|---|---|
| Cipher enumeration stopped before the server ran out of suites | Strong | **Ungraded** |
| A certificate chain that is both expired and untrusted | reported *trusted* | reported **not trusted** |
| A CAA lookup that stopped before reaching the top of the tree | "no CAA found" | "the search stopped at *x*; not established either way" |

The first is the one to know about if you gate on this. A truncated list can
support *something weak is here* and cannot support *nothing weak is here*, and
`strong` is the verdict that claims an absence. The host decides when to stop
answering, so `ungraded` is a state the scanned party can choose — which is
why the command line now exits `4` for it rather than `0`.

The second was a real misreading: Go checks a certificate's dates before it
looks for an issuer, so `Expired` is what it returns for an expired
certificate whether or not anything would ever have vouched for it. Trust is
now re-asked at a moment the certificate was valid.

### Things now graded that were not looked at

- **A certificate served only at an older protocol version.** A server picks
  its certificate from what the client offered, so an old client can be handed
  a different one. Every version that completes a handshake is compared by its
  leaf's own bytes, and a chain that differs is graded in full. The worse of
  the two sets the verdict.
- **Extended key usages the Go standard library has no name for.** They were
  dropped from the report, which read as though the certificate carried
  nothing else.

### Documents cited

- RFC 8446 replaced by **RFC 9846**, which obsoletes it.
- **RFC 10015** added, for the finite-field and static key exchange rules.
- **RFC 9150** added, for the integrity-only suites.

Each citation is checked against rfc-editor.org for an obsoleted or updated
banner at every policy review. The next review date is in
`internal/policy/policy.go`.

---

## What did not change

Grading is still worst-case: one insecure option makes a configuration
insecure, however many strong options sit beside it, because an attacker
chooses which to negotiate.

Refusing an obsolete protocol version is still not graded. A server that
declines TLS 1.0 has done the right thing, and a finding attached to that
refusal would report a correct configuration as insecure.

Issuance policy is still reported and not graded. It comes from a resolver
rather than from the connection, and it describes a system the person who
configured the server often does not administer.
