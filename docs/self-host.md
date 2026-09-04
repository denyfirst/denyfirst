# Running it yourself

This is the tool. The site is a demonstration of it.

Until 2026-09-03 anybody could point denyfirst.dev at any host on the internet
and that server opened the connections. It put this project in the worst
position available to it: ours was the address in the scanned party's logs,
and we had deliberately made ourselves unable to say who had asked, because
recording that is the one thing this project undertakes not to do. There were
two ways out — start keeping records, which is not available, or stop
connecting to third parties. This is the second.

So the scan runs on your machine, from your address, under your
responsibility. The public deployment reaches only hosts this project owns.

What that buys you is not only ours to give up.

**The promise becomes a fact.** The hosted service says it records nothing and
you have to believe it. Here there is nothing to believe: this project is not
in the path. *I don't even have the data to begin with* is a stronger
statement than any policy.

**The restrictions that exist for a public service do not apply to you.** They
are there so that a stranger cannot use somebody else's server through ours,
and you are not a stranger to your own network:

| | hosted | yours |
|---|---|---|
| private and loopback addresses | refused | `-allow-private` |
| ports | eight implicit-TLS ports | any |
| bare IP addresses | refused | accepted |
| which hosts | the ones this project owns | whichever you point it at |

---

## Get a binary, and check it before you run it

Every release carries `SHA256SUMS` and an OpenSSH signature over it, and a
workflow rebuilds each release on a machine the maintainer does not control.

**[`docs/verify.md`](verify.md) has the procedure.** It is not repeated here,
because two copies of a verification procedure drift and the copy nobody is
reading is the one that goes wrong. Do that first; everything below assumes a
binary you have checked.

Building from source is the other answer, and needs nothing but Go:

```sh
git clone https://github.com/denyfirst/denyfirst
cd denyfirst
go build ./cmd/denyfirst-scan ./cmd/denyfirstd
```

`go.mod` has no `require` block. Nothing is fetched beyond the standard
library, so there is no third-party supply chain to audit here.

---

## The command line

```sh
./denyfirst-scan example.com
./denyfirst-scan -json example.com
./denyfirst-scan -allow-private 10.0.0.5
```

The exit status is the worst verdict found — `0` strong, `1` weak, `2`
insecure, `3` the scan could not be completed — so it gates a pipeline without
anything having to parse the output.

### Two checks

`-check` selects which one runs, and the default is the one that has always
run. A default that quietly started running a second check would change the
exit status of a pipeline nobody touched.

```sh
./denyfirst-scan example.com                 # the transport and its certificates
./denyfirst-scan -check web example.com      # how the site is reached over HTTP
```

The web check answers what a TLS report cannot: whether the site is *also*
served in the clear, whether the plaintext address sends a visitor to the
secure one, and whether anything tells a browser to come back over TLS. A host
can negotiate TLS 1.3 with an immaculate certificate and still hand every
visitor's first request to whoever is on the path.

It sends **one `GET` of `/`** over each scheme, reads the headers, closes the
body unread, and follows only the addresses a `Location` header names. It
never requests a path of its own choosing. `docs/invariants.md` N7 has the
whole discipline.

The two rule sets are separate and never comparable with each other:
`denyfirst-tls-v6` grades a handshake, `denyfirst-web-v1` grades an HTTP
response. `-version` prints both, and every report names the one that produced
it.

```sh
./denyfirst-scan -check web -limits          # what a header check cannot establish
```

## The service

```sh
./denyfirstd -listen 127.0.0.1:8080
```

Loopback by default, so an accidental start is not immediately public.
`denyfirstd -h` lists every limit and its default.

---

## In a container

The image has **no base system**: no package manager, no shell, no libc.
There is nothing in it to update and nothing in it to take. It also builds
nothing — a builder stage would produce bytes nobody has checked, and the
argument of this project is that the release is signed and reproducible. So
the image is a wrapper around the binary **you verified**.

```sh
curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/v0.13.0/denyfirstd_v0.13.0_linux_amd64
# verify it — docs/verify.md
mv denyfirstd_v0.13.0_linux_amd64 denyfirstd
docker compose up -d
```

Then `https://localhost` — or whatever certificate you put in front of it.

### The trust store comes from your machine

`docker-compose.yml` mounts `/etc/ssl/certs` read-only into the container and
points `SSL_CERT_DIR` at it.

This is not a convenience. Every verdict about a certificate chain is a
verdict *against some trust store*, and a report should reflect yours rather
than one baked in by whoever built an image. The standing limits already say
that a scan consults one trust store; this is where you choose which.

**An empty store does not fail — it reports every certificate as untrusted.**
The chains still verify, they verify to nothing, and every report says the
scanned server does not reach a trusted root: a finding about your container
printed as a finding about somebody else's server. So the service
refuses to start when it cannot find a store, rather than producing
confident nonsense.

### What the compose file takes away

`read_only: true`, `no-new-privileges:true`, `cap_drop: ALL`, and an
unprivileged user. The container binds 8443 and the host publishes 443, so
nothing inside needs the capability to bind a privileged port.

---

## What is yours now

The scan leaves your machine and your address is in the logs of whatever you
point it at. That is the arrangement working as intended, and it is also a
responsibility that used to be ours.

Scan what you own, what you administer, or what you have permission to scan.
This tool sends nothing but a standard client hello at each TLS version and
closes the connection when the handshake finishes — no exploit, no malformed
packet, no HTTP request — but a scan is still a connection somebody else pays
for, and thirteen to fifty of them is still thirteen to fifty.

The licence is AGPL-3.0. Run a modified version and offer it to others, and
the modifications have to be available to them. That is the point of the
licence for a tool whose value rests on being checkable.
