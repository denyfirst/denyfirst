# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

**Preferred:** use GitHub's private vulnerability reporting — the *Security*
tab of this repository, then *Report a vulnerability*. This keeps the report,
the discussion, and the fix in one place and private until disclosure.

**Alternative:** email `security@denyfirst.dev`.
Reports may be encrypted. The key is at
[`https://denyfirst.dev/pgp-key.txt`](https://denyfirst.dev/pgp-key.txt) and
its fingerprint is:

    75B7 A18A 8971 5E37 75DB  CA2E A8D9 94D1 221A A045

This fingerprint is published in two places on purpose: here, and in
`security.txt` on the site. Whoever takes the domain serves their own key
beside their own fingerprint, and it would look exactly like the real one.
This repository is a different account behind different credentials, so
compare the two before encrypting anything.

The key certifies and encrypts and does nothing else. It is not the key that
signs releases; that one is an SSH key and points the other way.

Please include enough detail to reproduce: affected component, version or
commit, steps, and what an attacker gains. Proof-of-concept code is welcome.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days for high and critical |

This project is maintained by one person outside of a day job. If a deadline
slips you will hear why rather than hearing nothing.

## Disclosure

Coordinated disclosure, 90 days by default. If a fix ships earlier, disclosure
happens earlier. If the issue is being actively exploited, we publish
immediately with whatever mitigation exists.

Reporters are credited in the advisory and the release notes unless they ask
not to be. Anonymous and pseudonymous reports are accepted without question.

There is no bug bounty. This is an unfunded project and pretending otherwise
would waste your time.

## In scope

- The hosted instance at `denyfirst.dev`
- Source code in this repository
- Release artifacts and the workflows that produce them
- **The documentation**, on the same terms as the code. `docs/verify.md` and
  `docs/invariants.md` are instructions a stranger is meant to follow in order
  to check this project; a command in them that does not do what it says is a
  finding, not a typo. One already was: the rebuild recipe named a linker flag
  that changed the binary's hash, so every honest verifier got the exact result
  that means "tampered with".

Of particular interest, because these are where this project claims to be
careful:

- **SSRF and its bypasses.** `internal/safedial` refuses non-public
  destinations. DNS rebinding, IPv4-mapped IPv6, redirect chains, parser
  differentials between the validator and the dialer — if any of these reach a
  private address, that is a serious finding.
- **Data retention.** Anything that causes user-supplied input to be written to
  disk, to logs, or to a third party.
- **Anything this service tells one user about another.** A limit shared
  between users can answer questions about them by refusing; a counter can do
  it by moving. Both have happened here.
- **Amplification against a host being scanned.** One request becomes up to
  fifty handshakes somewhere else, and the per-target limit is the only thing
  between that and a service that can be aimed. A way past it, or a way to make
  one target's budget look like several, is in scope even though the victim is
  not us.
- **Content-Security-Policy bypass**, XSS, or any injected external request.
- **Supply chain.** Unpinned actions, dependency confusion, a compromised
  release path.

## Out of scope

- Missing headers with no demonstrated impact
- The *tuning* of a rate limit — that some number is too generous or too mean —
  absent an attack it enables. How the limits are *ordered* and what each one
  charges is a different question and is in scope: a refusal that spends the
  wrong budget is a real finding, and one of them was.
- Automated scanner output submitted without verification
- Social engineering, physical access, or attacks on third-party infrastructure
- Denial of service through raw traffic volume

## Safe harbour

Good-faith research under this policy is authorised and will not be met with
legal action. Good faith means: do not access, modify, or exfiltrate other
people's data; do not degrade the service; stop as soon as you have confirmed
the issue; report it before disclosing it.

This authorisation covers the hosted instance and this repository only. It does
not extend to third-party services, and it does not override the law.
