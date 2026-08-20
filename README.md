# denyfirst

A TLS and certificate scanner that cites its sources and keeps no records.

Point it at a server and it opens a real handshake at every TLS version, works
out which cipher suites the server will actually accept, and reads the
certificate chain it presents. Every verdict comes from a written rule set
with the document behind it attached, and every report states what it could
not measure.

Nothing about a scan is recorded. Not the hostname, not your address, not the
result.

---

## Why another one

There are several TLS scanners and they work. Three things here are
deliberately different.

**Every verdict names its source.** A finding that says a suite is insecure
links to RFC 9325, to RFC 8446, to the CVE. Disagree with a grade and you are
disagreeing with the document, not with us. The rules live in
[`internal/policy`](internal/policy) and are versioned, so the same server
graded by the same policy version gives the same answer next year.

**Every report says what it did not check.** Go's TLS stack implements
roughly twenty-seven of the three hundred suites in the IANA registry, and
gives a client no way to choose among TLS 1.3 suites. Revocation is not
checked at all. All of that is printed alongside the findings, because a short
list of problems can mean a well-configured server or a scan that could not
see very far, and a reader deserves to know which.

**Nothing is recorded.** There is no log of what was scanned, by whom, or
when. This is enforced by there being no code that could write one, and a test
fails if any appears. The only thing kept is a count of scans, which is
published on the site precisely because it identifies nobody.

---

## Using it

### The command line

```sh
go build ./cmd/denyfirst-scan
./denyfirst-scan example.com
```

```
denyfirst-scan example.com
denyfirst-scan example.com:8443 another.example.com
denyfirst-scan -json example.com
denyfirst-scan -allow-private 10.0.0.5
```

The exit status is the worst verdict found, so it can gate a pipeline: `0`
when everything is strong, `1` on a weak finding, `2` on an insecure one, and
`3` when the scan could not be completed.

The command line accepts bare addresses and any port. The hosted service does
neither, and the reasons are in [`internal/scan/scan.go`](internal/scan/scan.go).

### The service

```sh
go build ./cmd/denyfirstd
./denyfirstd -listen 127.0.0.1:8080
```

Then open `http://127.0.0.1:8080`. It listens on loopback by default so that
an accidental start is not immediately public.

```sh
./denyfirstd \
  -listen :443 \
  -tls-cert /etc/ssl/denyfirst.pem \
  -tls-key /etc/ssl/denyfirst.key \
  -stats-file /var/lib/denyfirst/stats.json
```

`denyfirstd -h` lists every limit and its default.

---

## Running your own

This is a supported use rather than a workaround. The service makes a promise
about what it keeps; running it yourself replaces that promise with a fact you
control.

```sh
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
go build ./cmd/denyfirstd
```

There are no third-party dependencies. `go.mod` has no `require` block, so
`go build` fetches nothing beyond the standard library and there is no supply
chain to audit here beyond Go itself.

The service is licensed under AGPL-3.0. If you run a modified version and
offer it to others, the modifications have to be available to them. That is
the point of the licence for a tool whose value rests on being checkable.

---

## What it does not do

Named rather than left to be discovered.

**No exploits.** No malformed packets, no Heartbleed probe, no ROBOT oracle,
no padding oracle. Only a standard client hello at each version. Everything
reported is what any client receives on connecting.

**No HTTP request.** The connection is closed as soon as the handshake
finishes. No path is tried, no header is sent, and the target's home page is
never fetched.

**No revocation check.** Asking a certificate authority whether a serial is
still valid would tell it which certificate somebody is looking at. A chain
reported as trusted reaches a root and is in date; it may still have been
revoked, and the report says so.

The report does say whether the server stapled a status response, because
that arrives in the handshake and costs nobody anything to observe. It says
no more: the response is not parsed, its signature is not verified, and its
serial is not matched against the certificate. A missing staple is a fact
rather than a fault — certificate authorities are no longer required to run
OCSP and several have stopped — so it is not graded. The one graded case is a
certificate that demands stapling under RFC 7633 and does not get it, which
breaks the connection for every client that honours the extension.

**No port scanning.** Only ports that speak TLS from the first byte: 443,
8443, 465, 636, 990, 993, 995 and 5061.

**No private addresses.** The dialler refuses private, loopback, link-local,
multicast and reserved ranges, resolves each name once, and connects to the
address it inspected rather than to the name.

---

## How it is put together

```
cmd/denyfirst-scan     the command line tool
cmd/denyfirstd         the service

internal/safedial      a dialler that refuses non-public addresses
internal/tlsprobe      handshakes: versions, cipher suites, the chain
internal/certinfo      what the certificate says, and whether it verifies
internal/policy        the rules, and the documents behind them
internal/scan          the pipeline both front ends share
internal/httpapi       the HTTP surface and its limits
internal/web           the pages
```

Two principles run through it.

**Measurement and judgement are separate.** `tlsprobe` and `certinfo` gather
facts; `policy` decides what they mean. That is why an upstream library
changing its opinion about a cipher suite does not silently change ours.

**Guards sit where the action happens, not where the request arrives.** The
port list is enforced in `internal/scan`, not in the HTTP handler, so it
survives a caller that does not exist yet.

---

## Verifying and contributing

- [`/.well-known/security.txt`](https://denyfirst.dev/.well-known/security.txt)
  — the machine-readable contact, in the RFC 9116 format
- [`docs/invariants.md`](docs/invariants.md) — what the project guarantees,
  where each guarantee is enforced, and which test protects it
- [`docs/verify.md`](docs/verify.md) — checking a release against its signature,
  and rebuilding it yourself
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability

Findings are welcome. This used to point readers at input parsing, on the
grounds that every bug so far had been found there; the first outside review
found more in the release procedure, the rate limits and the instrumentation
than in any parser, so that guidance was wrong and is withdrawn rather than
quietly reworded.

Documents are in scope too, and not as a courtesy. Several of those findings
were pages that no longer described the code — including one that told anyone
rebuilding a release to pass a linker flag naming a symbol this program does
not define, which changes the build ID and therefore the hash. The instructions
for proving a release untampered produced, for every honest reader who followed
them, the exact signature of tampering.

```sh
go test ./...                                                    # everything
go test ./internal/scan -run '^$' -fuzz FuzzSplitTarget           # one target
```

---

## Licence

AGPL-3.0. See [`LICENSE`](LICENSE).