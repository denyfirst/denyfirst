# denyfirst

Security tools that deny by default. No logs, no tracking, no third parties.

## What this is

A small set of security and privacy tools, built on one rule: **nothing is
permitted unless it is explicitly required.**

That rule is not a slogan. It is the actual architecture:

- No analytics. Not self-hosted analytics either. None.
- No cookies. No local storage. No session identifiers.
- No third-party requests. No CDN, no web fonts, no hosted libraries. Open
  DevTools and the network tab shows requests to this domain only.
- No logs of what you scanned. Requests are served and forgotten.
- No accounts, no sign-up, no email.

## How to verify that

Do not take our word for it.

**In your browser.** Open the network tab before you use a tool. Every request
should go to one origin. If you see a request to anywhere else, that is a bug —
please open an issue.

**In the source.** Every tool is here. The Go backend depends only on the
standard library where the task allows it, and every third-party module is
listed in `go.mod` with a note in `docs/dependencies.md` explaining why it
exists. The frontend has no build step: the JavaScript you receive is the
JavaScript in this repository.

**In the build.** Releases are built by GitHub Actions from a tagged commit.
The workflow is in `.github/workflows/`, the logs are public, and the
artifacts are signed. You can rebuild from the same tag and compare hashes.

## Tools

Nothing shipped yet. First release in progress:

- **TLS inspector** — certificate chain, protocol versions, cipher suites,
  HSTS, CAA records, certificate transparency. Server-side, nothing retained.
- **Metadata stripper** — EXIF and document metadata, viewed and removed
  entirely in your browser. The file never leaves your machine.

## Design constraints

These are decisions, not aspirations. They constrain what can be built here.

**Client-side by default.** If a tool can run in the browser, it runs in the
browser. Server-side work happens only when the task requires reaching the
network — a TLS handshake cannot be performed from a page.

**Strict Content-Security-Policy.** No `unsafe-inline`, no `unsafe-eval`, no
external origins. This rules out most of the modern frontend toolchain, which
is the point.

**Refuse private targets.** Tools that make outbound connections refuse
loopback, RFC 1918, link-local, and reserved ranges. A scanner that will
connect anywhere is an SSRF proxy wearing a nice interface. See
`internal/safedial`.

**Small dependency surface.** Every dependency is a party you are trusting on
behalf of the user. Each one has to earn its place.

## Running it yourself

The whole point of publishing this is that you do not have to trust the hosted
version.

```
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
go build ./cmd/denyfirst
./denyfirst
```

Requires Go 1.25.12 or later. No database, no configuration file, no environment
variables required to start.

## Contributing

Issues and pull requests are welcome. Two things to know before you start:

Changes that add tracking, analytics, external requests, or data retention will
be closed. This is not negotiable and is not a comment on the quality of the
patch.

Security issues go to `SECURITY.md`, not to the issue tracker.

## Licence

GNU Affero General Public License v3.0. See `LICENSE`.

AGPL rather than MIT for one specific reason: if you run a modified version of
this software as a network service, you must publish your modifications. A
permissive licence would let someone take these tools, add the tracking we
removed, and host them without disclosure. The licence is part of the promise.
