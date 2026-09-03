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

## `denyfirst-v6` → `denyfirst-tls-v6`

Unreleased. **No rule changed.** A report graded
`denyfirst-v6` and a report graded `denyfirst-tls-v6` are comparable in every
respect: the same twenty-four certificate rules, the same chain grading, the
same cipher and protocol verdicts, from the same source. Only the name of the
rule set is different, and this section exists so that a reader who notices
the change does not go looking for the rules behind it.

The name now carries the check as well as the number. This project has one
check and expects more — the first of them looks at how a domain publishes its
mail policy — and a number on its own stops meaning one thing the moment there
is a second rule set. `denyfirst-v7` over a mail report and `denyfirst-v7`
over a TLS report would be the same name over two different rule sets, which
is precisely the confusion the name is printed to prevent.

Renamed while there is one rule set to rename, for the same reason the check
moved to its own address in the same release: it costs nothing today and
cannot be undone cheaply once reports carrying the ambiguous name are in
somebody's pipeline.

Nothing else about a report changed. The rule identifiers are unchanged, so
anything tracking or suppressing a finding by its identifier is unaffected.

---

## `denyfirst-v5` → `denyfirst-v6`

Released in v0.11.0, 2026-09. **The rest of the chain is graded.** Until now
all twenty-four certificate rules looked at the certificate served for the
host and at nothing else: the chain was checked for trust — does it reach a
root — and never for strength. A report said

```
Chain   4 certificates, trusted
```

beside a `strong` verdict, and three of those four had been graded by nothing.
An intermediate signed with SHA-1, or holding a 1024-bit key, passed in
silence.

It matters more on an issuer than on a leaf. **A forged leaf impersonates the
names inside it; a forged intermediate issues certificates for any name at
all**, and every client that trusts the chain accepts them. That is the
argument `cert.leaf-is-ca` rests on, arriving from the other direction.

Nothing new is asked of the server. These are bytes the handshake already
delivered.

### Rules added

| Rule | Verdict | When |
|---|---|---|
| `chain.signature-sha1` | Insecure | An issuer carries a SHA-1 signature |
| `chain.signature-md5` | Insecure | An issuer carries an MD5 or MD2 signature |
| `chain.signature-algorithm-unrecognised` | Weak | An issuer's signature algorithm is not one this rule set knows |
| `chain.roca` | Insecure | An issuer's RSA modulus carries the RSALib fingerprint |
| `chain.rsa-key-too-small` | Insecure | An issuer holds an RSA key below 2048 bits |
| `chain.ec-key-too-small` | Insecure | An issuer holds a curve below P-256 |
| `chain.key-algorithm-unrecognised` | Weak | An issuer's key type cannot be sized by this rule set |
| `chain.expired` | Insecure | An issuer's validity has ended |
| `chain.not-yet-valid` | Insecure | An issuer's validity has not begun |
| `chain.expiring-soon` | Weak | An issuer expires within 30 days |
| `chain.critical-extension-unrecognised` | Weak | An issuer marks an extension critical that this checker does not recognise |

The identifiers are `chain.` and not `cert.` deliberately. A pipeline
filtering on `cert.signature-sha1` today would otherwise start receiving
findings about a different certificate under an identifier whose meaning it
had already fixed. A new identifier is additive; a widened one is a silent
change.

### What is deliberately not graded

**Names.** A wildcard shape, a missing subject alternative name, a common name
outside the SAN list are questions about a certificate presented *for a name*.
An issuer is not presented for one.

**Self-signature.** A root is self-signed; that is what a root is, and
`cert.self-signed` would fire on every complete chain.

**Validity length.** An authority is issued for ten or twenty years by design.
The leaf's limit would fire on every chain ever served.

**Being an authority, and holding `keyCertSign`.** On an issuer both are
required rather than suspect — the exact inverse of `cert.leaf-is-ca` and
`cert.key-usage-cert-sign`.

### And the root is not graded at all

A root is trusted because the client already holds a copy, **not** because of
the signature it carries. No client verifies that signature — one that did
would be asking a certificate to vouch for itself — so grading it would raise
an alarm about a risk nobody is exposed to, and roots predating SHA-256 are
still in every store doing no harm.

Any self-signed certificate in the chain is skipped, which is how a client
treats it too. Where the server sent one, the report says so and says why.

### What this means for a verdict

An insecure issuer makes the report insecure, by the same worst-case rule as
everything else: a chain is only as sound as the weakest certificate a client
has to accept to reach a root.

---

## `denyfirst-v4` → `denyfirst-v5`

Released in v0.8.0, 2026-09. Four rules, all of them read off a certificate
this scan already had, so nothing new is asked of the server: the same
handshakes, the same bytes, the same load at the other end.

All four grade something the report was **already displaying and grading with
nothing**. A reader saw `CA: true` beside a leaf certificate and found no
finding next to it.

### What a certificate says it may be

| Rule | Verdict | When |
|---|---|---|
| `cert.leaf-is-ca` | Insecure | Basic constraints say `cA:TRUE` on the certificate served for this host |
| `cert.key-usage-cert-sign` | Insecure | The key usage includes `keyCertSign` and basic constraints do not say `cA:TRUE` |

**`cert.leaf-is-ca`.** RFC 5280 does not forbid it and Go's verifier accepts
such a certificate for a hostname, so nothing else on a report catches it. The
Baseline Requirements do forbid it — a subscriber certificate must carry
`cA:FALSE` — and the reason is the size of what the key can do. A stolen leaf
key normally impersonates the names in that leaf. A stolen leaf key that may
sign issues certificates **for any name at all**, and every client that trusts
the chain accepts them.

Absent is not false. With no basic constraints extension the question was not
answered, and reading *not a CA* out of silence would be drawing a measurement
that did not happen.

**`cert.key-usage-cert-sign`.** The same power arriving by the other
extension. RFC 5280 permits `keyCertSign` only where basic constraints say
`cA:TRUE`, so a certificate carrying one without the other claims a power its
own constraints deny it, and clients disagree about which half to believe. Not
raised where `cA:TRUE` is also present: that is the rule above, and charging
one mistake twice reports it as two.

### What a certificate says its key may do

| Rule | Verdict | When |
|---|---|---|
| `cert.no-digital-signature` | Weak | The key usage lists purposes and `digitalSignature` is not among them |
| `cert.critical-extension-unrecognised` | Weak | The certificate marks an extension critical that this checker does not recognise |

**`cert.no-digital-signature`.** Every TLS 1.3 handshake and every ECDHE
handshake at TLS 1.2 has the server sign with its key, so a client enforcing
the extension can use neither. An absent extension means *any purpose* and is
not this case, exactly as with the extended key usage in v4.

**`cert.critical-extension-unrecognised`.** RFC 5280 requires a client that
meets a critical extension it does not recognise to reject the certificate.
Go's verifier does, so such a certificate already produced
`cert.chain-untrusted` — **with no reason attached**. The finding names the
extension by object identifier and says only what was established: that this
checker does not recognise it. Whether the clients an operator cares about
recognise it is not something a scan from here can see.

### What did not change

No existing rule changed meaning. Every verdict that moves under `v5` moves
because of something the certificate says about itself that `v4` displayed and
did not grade.

---

## `denyfirst-v3` → `denyfirst-v4`

Released in v0.4.0, 2026-08. Five rules added and three notes. Every one of
them is read off a certificate this scan already had, so nothing new is asked
of the server: the same handshakes, the same bytes, the same load at the other
end.

### A key made by a generator known to be broken

| Rule | Verdict | When |
|---|---|---|
| `cert.roca` | Insecure | The RSA modulus carries the fingerprint of Infineon's RSALib, CVE-2017-15361 |

RSALib built primes of the form `k·M + (65537^a mod M)`, with `M` the product
of the first *n* primes, instead of choosing them at random. Both primes of a
key were made that way, so the modulus satisfies `N ≡ 65537^(a+b) (mod M)` —
and a key of that shape can be factored from the public key alone by
Coppersmith's method, in weeks to months of computation, with no access to the
server. Millions of smart cards, TPMs and national identity cards were
affected in 2017; Estonia withdrew over 750,000 identity cards.

**Nothing here factors anything.** Detection is a residue test: by the Chinese
remainder theorem, `N mod p` must lie in the subgroup 65537 generates for every
prime `p` dividing `M`, and checking thirty-eight of those takes microseconds.
So the finding says what was established — that the key carries the fingerprint
of a generator known to produce factorable keys — and not what it implies. The
two are different claims, and only the first one was measured.

The test is a necessary condition rather than a sufficient one: a modulus with
no relation to RSALib would have to land inside the reachable set modulo all
thirty-eight primes at once. The published corpora report no false positives,
and the wording is chosen so that the report is still true if one exists.

Nothing about a report changes for a key from any other generator. Practically
every publicly trusted certificate carrying this shape was revoked in 2017, and
authorities have been required to refuse such keys since; where it still bites
is keys generated on a smart card or a TPM for a server somebody runs
themselves, which is exactly what this project expects to be pointed at.

### What the certificate says it is for, and about whom

| Rule | Verdict | When |
|---|---|---|
| `cert.no-server-auth` | Insecure | The extended key usage extension lists purposes and server authentication is not among them |
| `cert.wildcard-shape` | Weak | A name contains `*` somewhere other than as the whole of the leftmost label |
| `cert.cn-not-in-san` | Weak | The common name holds a hostname that the subject alternative name does not |
| `cert.serial-entropy` | Weak | On a publicly trusted chain, a serial number too small to hold the required randomness |

**`cert.no-server-auth`.** RFC 5280 makes the extended key usage list
exhaustive, so a certificate listing purposes and omitting server
authentication is a certificate for something else, and a client following the
document refuses the connection however correct the rest is. An absent
extension means *any purpose* and is not this case — absent is not the same as
excluding, and older certificates commonly carry none.

**`cert.wildcard-shape`.** RFC 9525 permits one form: a leftmost label that is
exactly `*`. `w*.example.com`, `a.*.example.com`, `*.*.example.com` and a bare
`*` were each matched by some client at some point and are matched by none now.
A name in one of those shapes is worse than a missing one, because whoever
issued it believes the host is covered.

**`cert.cn-not-in-san`.** Clients have matched names from the subject
alternative name and nowhere else since RFC 2818 was replaced, and the Baseline
Requirements say the common name, if present, must repeat one of those values
rather than add one. So a hostname there that is not in the extension is
matched by nothing while telling a reader the certificate covers it. Only
raised when the common name is trying to be a hostname: an authority's own
label, `R11`, and an organisation name are not accused of being one.

**`cert.serial-entropy`, and why the threshold is not 64.** The Baseline
Requirements have required at least 64 bits from a random source since 2016,
because a predictable serial lets an attacker who can influence a certificate's
contents mount a hash collision against its signature. But a serial carrying 64
bits of that output is uniform over `[0, 2^64)`, so its *value* has fewer than
64 bits half the time and fewer than 63 a quarter of the time: a rule demanding
64 would accuse half of every compliant certificate ever issued. What one
certificate can honestly show is that a serial is far too small to hold that
output at all — a compliant one lands below `2^32` about once in four thousand
million — so that is what this rule says, and it catches counters and sequences
rather than pretending to measure entropy. It is raised only for a chain that
reaches the trust store, because the requirement is the Forum's and a private
authority answers to whoever runs it.

### Two notes, which are not verdicts

A **small RSA public exponent** is reported when it is below 65537. The
Baseline Requirements say the exponent *should* be at least that, not that it
must, and inventing a verdict the document does not carry is how a rule set
stops being checkable against the document it claims to follow.

**How many names a certificate covers** is reported whenever it is more than
one, with a sentence about shared certificates once it passes twenty. One key
standing behind a hundred hosts is a fact about the arrangement rather than a
fault in it, and it is the fact that decides what a stolen key costs.

### One more note, and the only measurement that costs a handshake

Whether the server will negotiate **X25519MLKEM768**, a hybrid of X25519 and
ML-KEM-768, is now reported on a `Key exchange` line beside the cipher suites.

It is the reason to care about a key exchange at all in 2026: traffic recorded
today can be kept and decrypted by whoever first builds a quantum computer
large enough, which is why the attack is called *harvest now, decrypt later*.
Forward secrecy does not prevent it — that protects against a private key
stolen afterwards, not against the exchange itself being broken.

Reported and not graded, because no document this rule set follows requires a
hybrid yet, and a verdict invented here would be this project grading against
its own opinion.

Three answers, not two: accepted, declined, and not established. The hybrid is
defined for TLS 1.3 alone, so a server without it is never asked and the
report says so rather than reading the silence as a refusal.

**It costs the scanned server one extra handshake, and only where the question
exists.** Measured on a synthetic server: a full scan of a modern host went
from twelve connections to thirteen, and a TLS 1.2 server stayed at twelve.

### The report says which of three things a note is

No rule changed here, and no verdict. What changed is how a report is read.

Everything that is not a finding used to appear under one heading, *What this
did not measure*. Three kinds of sentence lived there: what the scan
established and does not grade, what it could not settle about the host in
front of it, and what this program never claims about any host. A scan of a
bank on 2026-09-01 put eleven sentences under that heading, of which three
were limits of the scan. Among the rest was a post-quantum key exchange that
had been measured and passed.

Notes now carry a kind, and the report has three sections: **Observed**, **Not
established for this host**, and **Limits of this method**.

**This changes the API.** `notes` was an array of strings; it is now an array
of `{"kind": "...", "text": "..."}`, and the same applies to the `notes` of
each component. Anything reading the field will need the `.text`. It is a
breaking change, made one day after the field first shipped in v0.4.0 and
recorded here rather than left for a reader to discover.

### A CAA record set reads the same twice

RFC 8659 gives `issue` and `issuewild` properties no ordering and no
precedence, and a resolver returns them in whatever order it likes. Two scans
of paypal.com a quarter of an hour apart named the same authorities in
different orders, and so did cloudflare.com and kapitalbank.az.

They are sorted now, in the facts as well as in the sentence, so a report on
an unchanged server does not move between scans. A diff full of changes that
did not happen is one where the change that did happen is lost.

### A report says how much of it was reached

A report described only rules unbroken and absences observed. On a `strong`
result the strongest sentence available was *Nothing here fell short of the
rules*, and four of five observations beside it named something the server
does not do.

v0.6.x answered that with a block of nine affirmative sentences. Read on the
live site, seven of the nine restated a table or a certificate row that was
already on the page — one of them word for word. The block is gone. What
replaces it is one line beside the verdict:

```
Coverage  Every cipher suite this server accepts was enumerated, the chain was
          checked against the trust store, revocation was read from a stapled
          response, transparency receipts were counted, and issuance policy
          was answered.
```

It says what the scan reached and never what it missed — gaps belong to **Not
established for this host**, once. It carries no marks and no colour: green
ticks beside an insecure verdict read as approval, and a red mark against a
name with no CAA record would be a grade this rule set deliberately does not
give.

A clause appears only when that thing was read, so a scan that reached nothing
says nothing.

### A verdict says what it means

Beside a weak or insecure stamp:

> Worst case: an attacker chooses which option to negotiate, so the weakest
> one a server accepts is the one that decides.

A server can be graded insecure with a trusted chain, a verified staple,
transparency, CAA and an accepted post-quantum group, and until now nothing on
the report said why one option outweighed the rest.

### Cipher order and key exchange are labelled

Both sat under the cipher table as prose with nothing in front of them, and
the key exchange — the one measurement that costs the scanned server an extra
handshake — was being read on a second visit rather than a first. They are
rows now, in the same grammar as the certificate block, and they stay with the
suites: a key exchange is a property of the transport, and filing it under the
certificate teaches a reader that `RSA 4096` and `X25519MLKEM768` are the same
kind of thing.

### API

`assurances` is removed, one release after it was added, and replaced by
`coverage`: a single string, empty when a scan reached nothing.
`certificate.hostnameMatches` and `certificate.inDate` stay.

### The limits of the method are on one page### The limits of the method are on one page

Four of the sentences a report carried were true of every scan and said
nothing about the host: which cipher suites this client is able to offer, why
TLS 1.3 suites cannot be enumerated, that no certificate authority is ever
asked, and that transparency receipts are counted rather than verified.

They are no longer printed on each report. Reports name how many there are and
link **/method**, which explains how a report is read and lists all four; the
command line prints them with `denyfirst-scan -limits`, which needs no
network. They are declared once in `internal/policy/standing.go` and the page
is generated from that declaration, so the two cannot disagree.

### One sentence was wrong, on about a third of hosts

`Revocation was not checked` was appended to every report. It was written when
nothing here parsed a stapled response, and v0.3.0 — which taught this project
to read one and verify it against the issuer — did not remove it. So a server
that staples was told both that revocation had not been checked and that the
stapled response had been read and verified, one line above the other.

The sentence is gone. What replaces it says only what is true on every branch:
no certificate authority is asked anything by this scan, and revocation is read
only from a response the server stapled. What that response did or did not
establish is said where it is known.

### What did not change

No existing rule changed meaning and no verdict moved. A report from
`denyfirst-v3` and one from `denyfirst-v4` are comparable for every server
that keeps to the documents these rules cite — which is nearly all of them.

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
