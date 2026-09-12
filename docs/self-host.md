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

### The last row is the one to read twice

`porchd` listens on `127.0.0.1:8080` by default, and on that address the row
above is exactly right: the only person who can reach it is you.

**Bind it to an interface a stranger can reach, without
`-verification-secret-file`, and you have built an open scanner.** Anyone who
can reach the port can point it at any public host on the internet, and it is
*your* address in that host's logs. That is the arrangement this project
dismantled for its own public deployment — see `docs/scope.md` — rebuilt inside
your network.

A default is a mitigation rather than a boundary: it is the thing somebody
changes on the afternoon they need the service reachable, without changing
anything else. The boundary is proof of control, it is one flag, and
`docs/verify.md` is how to set it up:

```sh
porchd -listen 0.0.0.0:8443 -verification-secret-file /etc/porch/secret
```

`porchd -version` says which of the two you have, so a deploy can read it
rather than trust a filename:

```
scans whatever it is pointed at              # no proof required
scans only domains it has been shown control of
```

This is written here rather than only in `docs/scope.md` because this is the
page somebody follows while setting the service up, and a warning they meet
after they have finished is a warning about something they have already done.

---

## Keeping your own results

Nothing is kept unless you say where to keep it. That is the default and it
does not change.

What changes on a machine you run yourself is whose data it is. The public
deployment holds nothing because it is the visible party in somebody else's
logs and cannot say who asked — a repository worth seizing. None of that
reasoning survives the move to your own machine: these are your scans, of your
own estate, because you asked for them.

```sh
porch-scan -results-dir /var/lib/porch/results denyfirst.dev
porch-scan -results-dir /var/lib/porch/results -history denyfirst.dev
```

```
denyfirst.dev
=============

  DATE         VERDICT    FINDINGS
  2026-08-14   weak       hsts.absent
  2026-09-12   strong     none

  All graded by porch-tls-v7
```

`porchd` takes the same two flags and writes to the same store, so a service
scanning on a schedule and a person at a terminal build one history rather than
two.

**It is never served over HTTP.** A browsable history of an estate's weaknesses
is a thing worth attacking, and `porchd` has no authentication at all. Reading
it back is `porch-scan -history`, which runs on the machine, makes no
connection and resolves nothing.

**Nothing is kept that a report does not already carry**: the date, the check,
the rule set, the verdict, and which rules were raised. No time of day, no
client address, no markup, no cookie value. Writing a report down does not
relax what a report may contain.

**The rule set is kept beside each verdict**, and `-history` says where in a
history it changed. A server that went from strong to weak because a rule got
stricter has not changed at all, and a table that showed those two rows side by
side without saying so would send somebody looking for a change that never
happened.

**No retention period is invented.** `-results-keep N` bounds a target's
history and drops the oldest first; unset keeps everything. A number this
project chose would be a threshold nobody can argue with, applied to your disk.

### In Docker

The container runs as `65534:65534` from a `scratch` image — there is no shell
in it and nothing to `chown` — so the directory has to be owned before it is
mounted:

```sh
mkdir -p porch-data && sudo chown 65534:65534 porch-data
```

```yaml
services:
  porch:
    image: porch
    ports:
      - "443:8443"
    volumes:
      - /etc/ssl/certs:/etc/ssl/certs:ro
      - ./porch-data:/data
    command:
      - "-listen=0.0.0.0:8443"
      - "-results-dir=/data/results"
    read_only: true
```

`read_only: true` stays. It locks the container's own filesystem; a mounted
volume is still writable, so nothing is given up to gain this.

`command:` replaces `CMD` and not `ENTRYPOINT`, so `-listen` has to be repeated
there or it reverts to the image's default.

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
go build ./cmd/porch-scan ./cmd/porchd
```

`go.mod` has no `require` block. Nothing is fetched beyond the standard
library, so there is no third-party supply chain to audit here.

---

## The command line

```sh
./porch-scan example.com
./porch-scan -json example.com
./porch-scan -allow-private 10.0.0.5
```

The exit status is the worst verdict found — `0` strong, `1` weak, `2`
insecure, `3` the scan could not be completed — so it gates a pipeline without
anything having to parse the output.

### Two checks

`-check` selects which one runs, and the default is the one that has always
run. A default that quietly started running a second check would change the
exit status of a pipeline nobody touched.

```sh
./porch-scan example.com                 # the transport and its certificates
./porch-scan -check web example.com      # how the site is reached over HTTP
```

### If the Issuance line says "not checked"

That row is the CAA record set: which authorities the domain allows to issue a
certificate for it. Reading it needs a resolver, and the resolver is this
machine's own — read from `/etc/resolv.conf` on unix, assembled from the
registry on Windows. Every one the machine has configured is tried in order,
because the second is there for exactly the case where the first does not
answer.

If it still says *not checked*, name one:

```sh
./porch-scan -resolver 192.168.1.1:53 example.com
```

Any resolver you would ordinarily use. There is deliberately no default: a
public resolver chosen by this program would quietly decide who learns which
names you are looking at, and that is your decision rather than ours.

The web check answers what a TLS report cannot: whether the site is *also*
served in the clear, whether the plaintext address sends a visitor to the
secure one, and whether anything tells a browser to come back over TLS. A host
can negotiate TLS 1.3 with an immaculate certificate and still hand every
visitor's first request to whoever is on the path.

It sends **one `GET` of `/`** over each scheme, reads the headers, closes the
body unread, and follows only the addresses a `Location` header names. It
never requests a path of its own choosing. `docs/invariants.md` N7 has the
whole discipline.

The three rule sets are separate and never comparable with each other:
`porch-tls-v7` grades a handshake, `porch-web-v3` grades an HTTP response, and
`porch-mail-v1` grades what a domain's DNS says about its mail. `-version`
prints all three, and every report names the one that produced it.

```sh
./porch-scan -check web -limits          # what a header check cannot establish
```

## The service

```sh
./porchd -listen 127.0.0.1:8080
```

Loopback by default, so an accidental start is not immediately public.
`porchd -h` lists every limit and its default.

---

## In a container

The image has **no base system**: no package manager, no shell, no libc.
There is nothing in it to update and nothing in it to take. It also builds
nothing — a builder stage would produce bytes nobody has checked, and the
argument of this project is that the release is signed and reproducible. So
the image is a wrapper around the binary **you verified**.

```sh
curl -fsSLO https://github.com/denyfirst/denyfirst/releases/download/v0.13.0/porchd_v0.13.0_linux_amd64
# verify it — docs/verify.md
mv porchd_v0.13.0_linux_amd64 porchd
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
