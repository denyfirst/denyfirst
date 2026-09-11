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

The hostname is resolved once **per connection**, and the resolved literal is
dialled, so a name that answers differently on a second lookup cannot redirect
the connection after it was checked.

Per connection, not per scan. That distinction was left implicit here and on
the privacy page — both said "resolved once", which reads as a claim about the
whole scan and is not one. A scan opens up to about fifty connections and
resolves the name for each, which is why a rotating answer set can hand them to
different machines; R3 is where that is reported. The rebinding property is
unaffected and is what this paragraph is about: within one connection, the
address that was checked is the address that is dialled.

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

Eight ports, all implicit-TLS: 443, 8443, 465, 636, 990, 993, 995 and 5061.
STARTTLS ports are deliberately absent — the probe speaks TLS from the first
byte, so 25 or 587 would fail in a way that reads as a fault of the server.

**Two locks, on different doors.** `Scanner.Scan` refuses the port for every
caller, which is why the check is there and not in the HTTP handler; and the
list is handed down to the dialer, so a prober reached without passing `Scan`
still cannot open the connection. The second was added on 2026-09-02 during an
audit: the check was correct and singular, and a guard in one place is a guard
somebody walks around by adding an entry point.

This is the invariant a description of the service has to be measured against.
The letter written to the hosting provider on 2026-09-01 said *port 443 and no
other*, which was never what the code did — see
`claude/denyfirst-accuracy-audit-2026-09-02.md`. A statement about this
project is worth what the code says, and the code is here.

*Enforced in:* `internal/scan`, in `Scanner.Scan`, unless `AllowAnyPort`;
`internal/scan.Scanner.prober`, passed to `internal/safedial.Dialer`
*Lifted by:* the command line only
*Guarded by:* `TestScannerEnforcesPortsByDefault`, `TestCheckPort`,
`TestAllowedPortsAreImplicitTLS`, `TestThePortAllowListReachesTheDialer`,
`TestTheAllowListReachesTheDialer`

### N4 — Every network operation is bounded

A per-attempt timeout multiplies by the number of addresses tried, so there is
also a total budget, and a cap on how many resolved addresses are attempted. A
caller's deadline is never extended.

*Enforced in:* `internal/safedial` (`Timeout`, `TotalTimeout`, `MaxAddrs`),
`internal/tlsprobe` (`HandshakeTimeout`, `TotalTimeout`),
`internal/httpapi` (`RequestTimeout`)
*Guarded by:* `TestCallerDeadlineWins`, `TestTotalTimeoutBoundsTheOperation`

---

### N6 — The public deployment connects only to hosts this project owns

Until 2026-09-03 anybody could point denyfirst.dev at any host on the internet
and this server opened the connections. That arrangement put the project in the
worst position available to it: **ours was the address in the scanned party's
logs, and we had deliberately made ourselves unable to say who had asked**,
because recording that is the one thing this project undertakes not to do.

Each half is a correct decision on its own. Together they are the worst of both
worlds — the visible party and the unattributable one at the same time, which
is not a position to argue from. The Hetzner abuse ticket of 2026-08 is that
shape, not an accident.

There are two ways out. Start keeping records, which is not available: the
promise is the point. Or stop connecting to third parties at all.

So the tool is run by the person who wants the answer, on their own machine,
from their own address, under their own responsibility. The public deployment
scans only hosts this project owns, as a demonstration that the instrument
works and that its verdicts can be reproduced by anyone who runs it.

**Compiled in, not configured.** A configuration difference is a security
boundary, and those are the boundaries that rot: a flag can be omitted, a file
can be edited, an environment variable can be missing and nothing looks wrong.
Under the `demo` build tag the list is in the binary and there is no way to
widen it without building a different binary. Without the tag there is no
restriction at all, which is what the tool is for — a default that restricted
anything would quietly limit somebody scanning their own network.

**The gate is the tag, not the length of the list.** Written the other way —
refuse only when a list is non-empty — a list emptied by a bad merge would open
the deployment to the whole internet and every test would still pass. This way
an emptied list refuses everything, which fails in the safe direction and is
caught by a test that says the demonstration has nothing to demonstrate on.

**The list matches at label boundaries.** The exclusion list (N8) matches
that way too, and there a mistake keeps a host out that should be in. Here a
mistake lets a host in that should be out, which is how somebody would arrange
to have us scan them: register `denyfirst.dev.example.com` and a plain suffix
match hands them our address.

**Checked in `Scanner.Scan`**, not in the HTTP handler, so it holds for the
command line built with the same tag and for anything written later — a guard
in one entry point disappears the moment a second one is added.

**The tag gates the list and nothing else.** Two builds of one program is a
boundary drawn by a build tag, and it is only as narrow as the files carrying
that tag. A test walks the tree and fails if a third file ever appears under
it: the demonstration build has to stay the tool with a list rather than
becoming a different program nobody tests. CI builds and tests it on every
change for the same reason.

**The page offers what there is, and says what it is.** A field that accepts
any hostname on a deployment that answers for a few is a control arguing with
its own server, and the visitor loses the argument. So the demonstration build
renders a menu rather than a field — keeping the id the script reads, because
a `<select>` answers `.value` exactly as an `<input>` does, and one script
serving both deployments has no branch in it to go stale. Beside it, at the
control rather than in the footer, the page says that this deployment scans
only hosts this project owns and where the tool is.

**The menu and the boundary are separate, and checked against each other.**
The boundary is a list of domains and decides what may be connected to; the
menu is a list of particular hosts with a sentence each and decides what a
visitor is offered. An entry on the menu that the scanner would refuse is the
page arguing with itself, so a test scans every offered host and fails if any
is refused.

**A refusal is answered in words and counted.** `Scanner.Scan` refuses the
host and that is where the property lives; the handler refuses it first so a
caller gets a sentence and somewhere to go rather than a scan that failed, and
so it is counted as `not_demonstrated` rather than as a host that could not be
reached. A figure rising there would say visitors are asking for something
this deployment does not do — which is how we would learn that the page is not
explaining itself.

**The list is not part of any check.** What this deployment may reach is a
property of the deployment, and every check asks the same question of it. It
lived inside the TLS scanner until 2026-09-05, which meant the web check would
have imported the TLS scanner to find out what it may connect to, and a mail
check after it — the shape that gets worse with every check added. It is
`internal/demo` now, and each check's own scanner asks it.

**Each check asks it where its own scan is decided.** `Scanner.Scan` for the
transport, `webscan.Scanner.Scan` for the web check — not in the HTTP handler
that happens to call one of them today. The web check was given the guard on
2026-09-06, *before* it had an address on the service at all, and that order
is the point: an entry point written later inherits the refusal instead of
having to remember it. A guard in one place is a guard somebody walks around
by adding an entry point, and adding entry points is exactly what this project
is now doing.

**A target is checked for validity before it is checked for permission.**
Asked the other way round, a demonstration build answers *this deployment does
not demonstrate that* to somebody who typed a port or a scheme, which tells
them the wrong thing about their own mistake. The probe defines what a target
is, so the probe is what is asked: `webprobe.CheckHostname` is exported for
exactly this.

**Two rules hold the build tag.** Every file gated on it is named `demo_*.go`,
so the whole boundary can be listed without reading the tree; and outside
tests the tag gates exactly the two files that declare the list. Most of the
HTTP tests scan hosts the list does not cover, and bending forty of them to a
deployment restriction would be the restriction dictating to the tool — so CI
names and drives the demonstration's own test instead, and greps the log for
it, because a `-run` pattern that matches nothing passes silently.

**The binary carrying the property is the binary that is released and
deployed.** A restriction compiled into a build is worth nothing until that
build is the one running, and a build that runs here is one that was released:
signed, listed in `SHA256SUMS`, and rebuilt by the reproduction workflow like
every other artifact. `scripts/build.sh` produces
`denyfirstd-demonstration_<tag>_linux_amd64` — Linux and amd64 only, because
this is not a thing to download and use but a thing one server runs, and
offering it for five platforms would invite somebody to install a crippled
scanner by mistake.

**A binary says which hosts it will connect to, and the deploy reads what it
says.** The two builds are indistinguishable from outside until one of them
refuses something: install the wrong one and the file is in place, the service
answers, the version matches, and the only symptom is a public scanner nobody
meant to run. So `-version` carries a third line, composed from the same list
the scanner enforces rather than from a constant of its own — a binary cannot
say one thing and do another — and the deploy procedure greps for it rather
than trusting a filename.

**One chain of guards, not one per entry point.** The web check has an address
now, and it walks the same chain the TLS check does: the client key, the read
allowance, the cross-site test, the content type, the scan allowance, the body
cap, the JSON decode, the exclusion list, the deployment list, the deadline,
the concurrency cap and the per-target budget. Twelve of eighteen steps are
identical, so a second handler would have been twelve copies of a guard, and
this invariant is about what happens to the copy nobody is looking at. What
differs is described as data — how a target is parsed, what budget it spends,
what runs, what is written — and the chain is written once.

The differences are small and each is a decision. The web check takes a bare
hostname, so a port is refused rather than dropped: ignoring it would discard
part of what somebody typed without saying so, which is the failure target
parsing already refuses for a path. Its budget is the host's HTTPS one rather
than a name of its own, because the per-target limit is the only one here that
protects the server being measured and a second budget would let one host be
made to absorb twice the peak. The scan allowance is shared, because two
endpoints each with a full one would silently double what a client can spend.

**And the list is asked about every host a redirect names.** The chain above
authorises the host somebody typed. A demonstration build that followed a
`Location` header off the hosts this project owns would be connecting to a
stranger from this project's address — this arrangement rebuilt through a door
nobody was watching, and needing no compromise to arrange, since a marketing
redirect to somebody else's platform is enough. N10 is that guard.

*Enforced in:* `internal/demo` (`demo.go`, `demo_on.go`, `demo_off.go`),
`internal/scan.Scanner.Scan`, `internal/webscan.Scanner.Scan`,
`internal/httpapi.Server.handleScan`, `internal/httpapi` (`check`, `target`),
`internal/web/assets/index.html`, `scripts/build.sh`, `docs/releasing.md`
*Guarded by:* `TestTheOrdinaryBuildIsNotADemonstration`,
`TestTheWebScannerRefusesAHostThisProjectDoesNotOwn`,
`TestARefusedHostIsNeverConnectedTo`,
`TestTheOrdinaryWebScannerIsNotADemonstration`,
`TestTheWebRefusalNamesNoHost`, `TestAMistypedTargetIsToldItIsMistyped`,
`TestEveryHostOfferedIsOneThisScannerWillReach`,
`TestTheTagSwitchesTheWebScannerToo`,
`TestTheDemonstrationListMatchesAtLabelBoundaries`,
`TestABlankEntryAdmitsNothing`, `TestTheBuildTagTouchesNothingElse`,
`TestTheDemonstrationBuildRefusesAHostItDoesNotOwn`,
`TestTheDemonstrationRefusalNamesNoHost`,
`TestTheDemonstrationListIsNotEmpty`, `TestTheTagIsWhatSwitchesIt`,
`TestEveryHostOfferedIsOneTheScannerWillReach`,
`TestTheDemonstrationPageOffersWhatItCanScan`,
`TestTheDemonstrationPageSaysWhatItIsAndWhereTheToolIs`,
`TestTheDemonstrationRefusalIsAnsweredAndCounted`,
`TestEveryRefusalCodeCanBeProduced`,
`TestTheWebEndpointWalksTheSameChainOfGuards`,
`TestTheWebEndpointRefusesAPortRatherThanDroppingIt`,
`TestOneScanAllowanceCoversBothChecks`,
`TestTheTargetBudgetIsSharedBetweenTheChecks`,
`TestAnAddressIsRefusedTheSameWayOnBothEndpoints`,
`TestTheHandlerNeverAcceptsATargetTheProbeWouldRefuse`,
`TestTheWebTargetIsFoldedBeforeAnythingSeesIt`,
`TestTheWebEndpointDoesNotAnswerAGet`,
`TestAVersionSaysWhichHostsTheBinaryWillReach`,
`TestTheVersionOutputCarriesTheReachLine`,
`TestTheDemonstrationBuildIsReleasedAndDeployed`

---

### N7 — An HTTP request is one GET of the root, and no path is ever invented

A TLS handshake stops at the transport. An HTTP request enters the
application: it lands in an access log with a path, it reaches whatever sits
in front of the origin, and on a badly built application a GET can change
state. That difference is why the web check is a separate package with its own
rules rather than a few more fields on the TLS probe, and why the discipline
is compiled in rather than left to whoever calls it.

**One `GET` of `/`, over HTTPS and over plaintext.** Nothing else is
requested. After the first request the only addresses fetched are the ones a
`Location` header named, resolved against the address that sent them exactly
as a browser resolves them. **No path is constructed by this program.** There
is no probing of `/admin`, no guessing under `/.well-known`, and no second
guess of any kind: this reads what a server volunteers to every visitor.

**The body is never read.** Headers are taken and the body is closed unread,
so a large or slow response costs a header's worth of traffic. It is also the
part the scanned server pays for.

**Only headers this check reads are kept.** An allow list, not a deny list.
A response carries whatever the server chose to send — internal host names,
software versions, request identifiers — and a report built from a deny list
holds all of it until somebody thinks of the next entry. Adding a rule that
reads a new header means adding the header to that list, which is a line a
reviewer sees.

The list drifted ahead of the rules once and it is worth naming, because a
list of things nobody reads is the state this rule exists to prevent: thirteen
headers were collected and two were graded, so eleven were held on the
strength of an intention. They are read now — one graded, the rest reported —
and a header kept without a rule that reads it is a header to remove rather
than to keep for later.

**A cookie's value is never recorded, and there is nowhere to put one.**
`webprobe.Cookie` carries the name and the attributes that decide whether a
cookie is safe — including `Path` and `Domain`, which a `__Host-` prefix
constrains and which cannot be checked in part: a browser that finds any one
of the three conditions wrong rejects the cookie outright, so reading two of
them would report a guarantee no browser is making. It has no value field at all: a value is a session identifier
as often as not, a report is a thing people paste into issue trackers, and a
struct with nowhere to hold a secret cannot leak one through a later change
that looked harmless. The value is discarded where the header is parsed, not
where the report is rendered.

**The chain is bounded and the boundary is recorded.** Five redirects, an
overlong `Location` refused, a `Location` in another scheme refused, and
credentials stripped from one before it is followed. Each refusal is written
into the chain, because a reader who cannot tell *it stopped here* from *it
was not followed* cannot interpret the chain at all.

**The guard is under the transport, not in front of the first request.** The
first address is one the operator chose; every address after it was chosen by
the server that answered. So the dialler is `safedial`, and it is given the
two ports a website is reached on — a redirect naming port 22 is this program
being aimed by the host it is measuring. No proxy is read from the
environment: one would put a third party in the path and the measurement would
then describe the proxy.

**The client says who it is.** The user agent names the tool and an address
that explains exactly what is sent. There is a field for saying who you are
and none for saying nothing: a probe that hides is one an administrator can
only be alarmed by, where one that identifies itself is one they can make a
decision about.

**And the address leads somewhere.** That promise is worth exactly as much as
the page behind it, and `/web/method` answered 404 from the day the user agent
first named it until the check had a service surface — at which point the
address started reaching strangers' access logs for real. A 404 makes a probe
look like it is hiding, to the one reader who went looking, which is the
opposite of what identifying yourself is for.

Nothing caught it. Internal links are followed against the routing tables, but
that reads the pages; this is an address the program puts into a request it
makes to somebody else, and it was covered by neither direction. It is
checked now, and the page answers the log reader before it answers the report
reader: somebody who arrives from a log line did not choose to be here and
wants one thing, which is what reached their server and the fact that there is
nothing else to look for.

*Enforced in:* `internal/webprobe`
*Guarded by:* `TestOnlyTheRootIsRequestedUnlessTheServerSaysOtherwise`,
`TestARedirectChainIsRecordedInOrder`,
`TestTheRedirectLimitStopsTheChainAndSaysSo`,
`TestARelativeLocationIsResolvedAgainstTheAddressThatSentIt`,
`TestALocationWithAnotherSchemeIsNotFollowed`,
`TestALocationCarryingCredentialsIsStrippedBeforeItIsFollowed`,
`TestAnOverlongLocationIsNotFollowed`,
`TestOnlyTheGradedHeadersAreRecorded`, `TestACookieValueIsNeverRecorded`,
`TestCookieAttributesAreRead`, `TestTheScopeAttributesAreRead`,
`TestTheScopeAttributesDidNotAddSomewhereForAValue`,
`TestTheRecommendedHeadersAreReportedAndNotGraded`, `TestTheBodyIsNotRead`,
`TestTheUserAgentIdentifiesTheToolAndWhereToReadAboutIt`,
`TestAnEmptyUserAgentIsNotAvailable`, `TestABareHostnameIsRequired`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestTheDefaultDiallerRefusesPortsOtherThanEightyAndFourFourThree`,
`TestTheClientFollowsNothingByItself`,
`TestNoProxyStandsBetweenThisAndTheHost`,
`TestTheTwoChainsAreIndependent`,
`TestEveryAddressThisProjectSendsOutResolves`

---

### N8 — Some names are refused before anything connects to them

A short list of defence and intelligence names, plus anyone who asked to be
left out. A TLS handshake is harmless; a handshake against a defence network,
described afterwards by somebody who was not asked, is a conversation this
project has nothing to gain from.

**The list is short on purpose.** A long one goes stale, and a long one that
has gone stale says something worse than nothing: that this project decides
which organisations deserve protection and got the answer wrong. `.gov` is
deliberately absent — most of what sits under it is an ordinary public website
a citizen's browser reaches daily, and refusing to look at one would suggest
this tool does something such a site needs protection from.

Anyone who would rather not be scanned is added on request, from an address at
the domain or one listed in its WHOIS or `security.txt`. That route handles
far more real cases than any list written in advance, and the additions are
kept in a separate variable so a copy of this project starts with the same
defaults and its operator's additions stay their own.

**It matches at label boundaries.** `mil` must exclude `army.mil`, must not
exclude `example.mil.com`, and must not exclude `domil.com`. A plain suffix
test gets the last two wrong, and the third is the one that would go
unnoticed. The comparison folds case and a trailing dot on its own rather than
trusting a caller to have done it, which is the argument N3 makes about where
a guard belongs: `EXAMPLE.COM`, `example.com` and `example.com.` are one
server.

**Every check asks it, and asks it where the connection is decided.** The list
is a property of this project rather than of any one check. The TLS scanner
asked it from the beginning; the web check did not, so until 2026-09-10 a name
on it was refused by `-check tls` and scanned by `-check web` — one guard, one
caller, and a second caller that walked around it, which is the failure N6 is
about arriving through the door N6 predicted.

**It is not part of any check.** It lived in `internal/scan`, which meant the
web check would have imported the TLS scanner to find out what it may connect
to, and a mail check after it — the shape that gets worse with every check
added. It is `internal/exclusion` now, extracted exactly as `internal/demo`
was on 2026-09-05 and for the same reason.

**It is asked before any source of authority, and nothing overrides it.** A
deployment list says which hosts an installation is *for*; this says which
names this project will not touch, whoever is asking and whatever they have
proven. Both refuse, so on the ordinary build the order decides only which
sentence is returned and no test without the demonstration tag can see it — a
sabotage that swapped them escaped every one. It is pinned under the tag
instead, because the order stops being cosmetic the moment a second source of
authority exists: a deployment that establishes its scope at run time
(`docs/scope.md`) must not be able to buy a scan of a name on this list by
proving control of it.

**And it holds at a redirect.** A name on this list was refused when typed and
reached when a `Location` header pointed at it, until the web probe began
asking the caller's boundary about every host a redirect names. N10 has the
reasoning; it applies to this list, to the demonstration list and to a verified
zone alike, because all three answer the same question about the same kind of
address.

**The refusal states the rule and does not repeat the name** (I3).

*Enforced in:* `internal/exclusion`, `internal/scan.Scanner.Scan`,
`internal/webscan.Scanner.Scan`, `internal/httpapi.Server.handleScan`
*Guarded by:* `TestExcludedNamesAreRefused`,
`TestExclusionMatchesAtLabelBoundaries`,
`TestOrdinaryGovernmentSitesAreNotExcluded`,
`TestExclusionIgnoresCaseAndTrailingDot`, `TestOperatorCanAddNames`,
`TestScannerRefusesExcludedNames`, `TestTheWebScannerRefusesAnExcludedName`,
`TestTheWebExclusionRefusalNamesNoHost`,
`TestTheWebScannerScansANameThatIsNotExcluded`,
`TestTheExclusionListIsNotOverriddenByTheDeploymentList`,
`TestEveryRefusalCodeCanBeProduced`

---

### N9 — A deployment scans only estates it has been shown control of

The command line needs no boundary: whoever runs it has the machine, the scan
leaves from their own address, and nobody else can reach it. A service is the
other case entirely, and until this existed it had nothing at all. A
`denyfirstd` bound to an interface is reachable by a careless colleague, by a
compromised CI job, and by an SSRF into the scanner — and every scan any of
them starts puts the operator's address in a stranger's logs. That is N6's
arrangement rebuilt inside somebody's own network, which is the thing
`docs/scope.md` was written to stop.

**Proof is a TXT record at `_denyfirst-challenge.<domain>`** carrying the token
this deployment expects for that domain. Publishing it needs control of the
zone, which is what is being proven.

**Or a file at `/.well-known/denyfirst-challenge`**, for teams without access
to their own DNS — which is a common enough arrangement that refusing them
would mean refusing the estates this tool is for.

**The two do not prove the same thing, so they do not grant the same thing.** A
record in a zone is a statement about the zone and covers every name under it.
A file on a host is a statement about that host: it opens that hostname and no
other, not its parent and not a name beneath it. Reading a file as a zone proof
would let one file open every name under a domain, including the ones delegated
to somebody else.

**And a file does not open a check that leaves the ports a browser uses.** It
proves control of what one hostname serves over HTTPS, which is exactly what a
web check reads. It proves nothing about port 993 on the same name: a content
network can serve the file while the mail service answers from an origin the
person who placed it does not administer. So `Covers` is told which surface is
asking, and only the zone proof answers for all of them.

**The fetch is the dangerous half.** It is a connection this deployment opens
to a host somebody named, before the boundary has decided anything — the shape
of the SSRF this exists to survive. It dials through `safedial` as a scan does,
over 443 and no other port, follows no redirect, reads a bounded body, and
verifies the certificate: a challenge read over a connection this program would
not trust proves nothing, because whoever can answer for the name can serve any
file.

**It is the one path this project constructs, and that is not a contradiction
of N7.** N7 governs the web check, which reads what a server volunteers and
guesses at nothing. This is not a check. It is one request for a file an
operator deliberately placed, made only when the DNS proof was not found, to a
host that will not be scanned unless the file is there. Nothing it returns
reaches a report.

**The token is derived per domain, not shared.** One secret published
everywhere would be readable in public DNS: anybody who looked at one record
could publish the same string on a name they control — including a name
pointed at somebody else's address — and have this deployment scan it. The
token is an HMAC over the deployment secret and the domain, so reading one
tells nobody anything about another.

**The secret is read from a file.** A flag value is in the process list, where
every user on the machine can read it, and in whatever unit file or shell
history put it there. It is the whole of the proof.

**Nothing is remembered.** A verification checked once and stored is a standing
authorisation outliving the relationship it came from: a domain changes hands,
a supplier contract ends, a subsidiary is sold. Re-reading is one round trip,
and it makes revocation work by deleting the record — the only revocation an
operator will actually find.

**Asked where the scan is decided**, beside `demo.Refusal` and the exclusion
list, in `Scanner.Scan` and `webscan.Scanner.Scan` rather than in the handler
that calls one of them today. Checking at startup and holding a flag would make
it a configuration boundary, and N6 says what happens to those.

**And asked after the exclusion list.** Proving control of a name does not put
it back in reach: the list says what this project will not touch, whoever asks
and whatever they have shown (N8). Asked the other way round, an operator is
told to publish a record for a name that will be refused after they publish
it — work this program prompted and that changes nothing.

**A scope that cannot check refuses.** A deployment configured to require proof
and given no resolver, or no secret, admits nothing. The message says the
failure is local rather than blaming the host, and the process refuses to start
if the secret file cannot be read: a service that was asked for a boundary,
could not build one, and scanned anyway is the failure this exists to prevent
arriving through a typo in a path.

**A lookup that failed is not a domain that is unverified.** Reporting the
second sends an operator to their DNS to publish a record they have already
published, rather than to the resolver that would not answer.

**Configured once, inherited by every check.** This is the half that was
missing, and it was missing in production while every test passed. Both
scanners asked the scope, both had tests proving they asked it, and
`httpapi.New` built the web check from nothing — so a service that configured a
boundary refused an unproven host on `/api/v1/tls/scan` and measured it on
`/api/v1/web/scan`. The component was secure and the composition was not.

N6 puts a guard where the connection is made, and it does. What N6 does not say
is that **a guard every constructor has to remember to pass is a guard somebody
forgets.** So the caller configures the boundary on the scanner it hands to
`New`, and every check the service builds takes it from there — including
through `UseWebScanner`, which is a door for tests and therefore exactly how a
boundary comes to be off in production. A replacement that carries no scope
inherits the one the server was built with rather than replacing it with
nothing.

The test for this drives the addresses rather than the packages. It reads the
`POST` routes out of the source, posts an unproven name to each, and asserts
that no dial was attempted and that the challenge was actually looked up — so a
check added later is tested by existing, and a refusal that arrives without a
lookup is not mistaken for this boundary holding.

**The refusal is recognised, not repeated.** Unlike the exclusion list and the
demonstration list, this boundary is a lookup, so asking it in the handler and
again in the scanner would be two queries somebody else's resolver serves for
one request. The scanner asks; the handler reads the answer and turns it into
`not_verified` with a 403. Before that it arrived as `scan_failed` with a 502
saying the target could not be reached — a sentence about somebody else's
server for a decision made entirely here, and a deliberate refusal counted as a
failure in the only figures an operator has to watch this service by.

**It is opt-in today, and that is the open state.** Turning it on by default
would stop every deployment that has not published a record yet, which is a
change to make deliberately rather than as a side effect of an upgrade.
`docs/scope.md` says the default belongs on for a service, and the roadmap
carries the gap until it is.

*Enforced in:* `internal/verify`, `internal/challenge`,
`internal/scan.Scanner.Scan`, `internal/webscan.Scanner.Scan`,
`internal/httpapi.New`, `internal/httpapi.Server.UseWebScanner`,
`cmd/denyfirstd.verificationScope`
*Guarded by:* `TestAPublishedTokenCoversTheZone`,
`TestADomainThatProvedNothingIsRefused`,
`TestATokenFromOneDomainDoesNotProveAnother`,
`TestATokenFromAnotherDeploymentIsNotAccepted`,
`TestTheTokenIsFoundAmongOtherRecords`,
`TestAScopeThatCannotCheckRefuses`,
`TestALookupFailureIsNotAnUnverifiedDomain`,
`TestTheRefusalNamesNoHost`,
`TestTheWalkDoesNotReachForAPublicSuffix`,
`TestTheMostSpecificNameIsAskedFirst`,
`TestATokenIsStableAndSpellable`,
`TestTheTLSScannerRefusesAnUnverifiedNameBeforeDialling`,
`TestTheTLSScannerScansAVerifiedName`,
`TestTheTLSScannerNeedsNoProofByDefault`,
`TestAnUnverifiedNameIsRefusedBeforeAnythingIsDialled`,
`TestAVerifiedNameIsScanned`, `TestNoScopeMeansNoProofIsRequired`,
`TestAnExcludedNameIsRefusedAsExcludedRatherThanAsUnproven`,
`TestEveryScanningEndpointRequiresProofOfControl`,
`TestAProvenDomainReachesTheProbe`,
`TestTheConstructorGivesEveryCheckTheSameBoundary`,
`TestReplacingTheWebScannerCannotDropTheBoundary`,
`TestTheVerificationRefusalStatesTheRuleWithoutRepeatingTheTarget`,
`TestALookupFailureIsNotAnsweredAsUnproven`,
`TestAServedFileProvesTheHost`, `TestAServedFileProvesNoOtherName`,
`TestAServedFileDoesNotProveACheckThatLeavesTheBrowsersPorts`,
`TestTheZoneProofCoversEverySurface`,
`TestAFileWithTheWrongTokenIsRefused`,
`TestAFailedFetchIsNotAHostThatPublishedNothing`,
`TestAHostServingNoFileIsRefusedRatherThanErrored`,
`TestNoFetcherMeansOnlyTheZoneProofWorks`,
`TestAHostWithAZoneProofIsNeverFetchedFrom`,
`TestOnlyTheChallengePathIsRequested`,
`TestAMissingFileIsNoChallengeRatherThanAnError`,
`TestAnEmptyFileIsNoChallenge`, `TestARedirectIsNotFollowed`,
`TestAFetchFailureNamesNoInfrastructure`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestAChallengeIsNotReadOverAnUntrustedConnection`,
`TestAFileProofDoesNotOpenTheTLSCheck`,
`TestAFileProofOpensTheWebCheck`,
`TestAFileProofDoesNotOpenAnotherName`

---

### N10 — A redirect is a connection the scanned server chose

Every boundary above authorises **the host the caller asked about**. A redirect
names a different one, and until 2026-09-10 the probe followed it: the
exclusion list, the demonstration list and the verified zone all held at the
front door and none of them held at the hop.

What that cost is not theoretical, and it is worst on the two deployments this
project is most careful about. A name on the exclusion list was refused when
typed and reached when a `Location` header pointed at it (N8). The
demonstration build — whose entire safety is a compiled-in list of hosts this
project owns — would have connected to a stranger the moment one of our own
hosts answered with a redirect off it, which is N6's arrangement rebuilt
through a door nobody was watching, and which needs no compromise to arrange:
a marketing redirect to somebody else's platform is enough. And a deployment
that scans only estates it has proven control of could be walked out of its own
estate by one header on a site it does own (N9).

`safedial` was never the answer to this. It stops a redirect reaching a
private, loopback or reserved address, which is a different question — the
hosts above are ordinary public ones.

**So the boundary is asked again, at the hop, before the address is dialled.**
The same three sources of authority, in the same order, written once in
`webscan.Scanner.reachable` rather than twice, so that an authority added later
cannot hold at the front door and not at the hop.

**The host asked about is not asked about again**, and no name is asked about
twice in one probe. Asking can be a DNS lookup somebody else's resolver serves;
a redirect from `https` to `http` on the same name is the commonest redirect
there is, and a chain of five hops on one host would otherwise be five
questions. The names are folded before they are asked or remembered, for the
reason N8 gives about its own comparison.

**A boundary that cannot be asked stops the chain.** A lookup that fails is not
permission — a guard that gives way whenever a resolver is slow is a guard
somebody can arrange to be slow.

**Asking is not free, and the cost is named rather than left to be found.** The
web check asks for the `HTTPOnly` surface, the same one it asks about the host
it was given, so a deployment that accepts the challenge *file* makes one
request to a redirect target before refusing it: a `GET` of the challenge path
over 443, identifying itself, following no redirect, with a capped body. "The
refusal comes before the connection" is therefore true of the probe and not
literally true of the machine, and a test that asserts nothing was dialled is
asserting the first.

The alternative — accepting only the zone proof at a hop, which costs a lookup
and no connection — was not taken. The file proof exists for teams with no DNS
access, and apex-to-www is the redirect almost every site has; those teams would
get a chain truncated at the first hop with nothing they could do about it. What
is spent instead is one fixed, published request, which is strictly less than
the full probe that used to happen there unasked.

**It is a parameter of `Probe`, not a field on `Prober`.** `Dial` is a field
because leaving it unset selects the safe answer; this has no safe default,
since the command line must follow a redirect anywhere and a service must not.
So it is spelled at every call site, where a review can see a `nil` — because a
guard a constructor has to remember to set is a guard somebody forgets, and
this project has already been caught by exactly that (N9).

**Declining is recorded, never silent.** The chain carries the reason in
`Stopped`, which is not `Truncated`: one is a limit of the method and the other
is a decision, and only one of them changes if the site is scanned from
somewhere else. The reason states the rule and does not name the host (I3) —
the `Location` header is one of the headers the probe keeps, so the reader has
the address without the report repeating it. And the reason is a string rather
than an error, because it is written into a report a stranger reads: an error
from the caller's boundary could carry a resolver's address, and a signature
with nowhere to put one is stronger than a rule saying not to (I6).

*Enforced in:* `internal/webprobe.Prober.chain`, `internal/webprobe.walk`,
`internal/webscan.Scanner.reachable`
*Guarded by:* `TestARedirectIsNotFollowedToAHostTheCallerRefuses`,
`TestARedirectIsFollowedToAHostTheCallerAllows`,
`TestANilReachFollowsAnyHost`,
`TestTheHostAskedAboutIsNotAskedAgain`,
`TestOneQuestionPerDistinctHost`,
`TestTheHostIsFoldedBeforeTheBoundaryIsAsked`,
`TestARefusedRedirectIsNotReportedAsTheRedirectLimit`,
`TestARedirectToAnExcludedDomainIsNotFollowed`,
`TestARedirectOutOfTheVerifiedZoneIsNotFollowed`,
`TestARedirectInsideTheVerifiedZoneIsFollowed`,
`TestARedirectIsNotFollowedWhenTheBoundaryCannotBeAsked`,
`TestTheRedirectRefusalNamesNoHost`,
`TestARedirectOffTheDemonstrationIsNotFollowed`,
`TestARedirectInsideTheDemonstrationIsFollowed`

---

### N11 — An address a certificate names is an address the scanned party chose

A certificate carries revocation list distribution points, and a scanner that
reads one is fetching an address written by the party it is measuring. A
certificate naming `http://10.0.0.1/` is that server aiming this scanner at the
network it runs in, and a certificate naming forty addresses is one scan turned
into forty requests somebody else pays for.

So the same guards every other outbound connection has: `safedial`, which
refuses private, loopback, link-local and reserved destinations; ports 80 and
443 only, because a port taken from a certificate would make this a port
scanner aimed by the target; `http` and `https` only, because a certificate may
name `ldap://` and following one means speaking a protocol the measured party
chose; no redirect followed, since that is an address chosen by whoever answered
an address chosen by the server; credentials stripped; and two distribution
points at most.

**And what comes back is believed only after it is verified.** A list arrives
over plaintext HTTP from an address a stranger named, so whoever can answer that
request chooses the bytes. Without a signature check against the issuing
certificate they could report a sound certificate as revoked — or, far worse, a
revoked one as sound. Four things are required before a single field is read:
the list parses, its signature verifies against the issuer, it is inside its own
validity window, and it arrived under the size cap.

**The size cap refuses rather than truncates**, and the direction of that
failure is the whole reason it matters. Every serial is absent from a truncated
list, and absence is exactly what "not revoked" is read from — so a list cut at
the cap answers *good* about a revoked certificate.

**A serial is compared as a number, never as bytes.** The same integer is
encoded with or without a leading zero byte depending on whether its top bit is
set, so a byte comparison reports a revoked certificate as sound for every
serial above `0x7f` — which is most of them, and which would pass every test
written with small numbers.

**Anything short of an answer is "not checked", never "not revoked"** (R4). The
report says which of the four failed, in this project's own words rather than in
a network error that would name a resolver or an address (I6).

**This is the one check that asks a third party, and the asking is bounded by
what it discloses.** Fetching a list tells an authority that somebody downloaded
a list; it does not say which certificate, because one list covers thousands.
That is a smaller disclosure than OCSP, which names the serial in the question,
and it is why this is done where OCSP is not. The demonstration deployment
promises on its privacy page that it asks no authority anything, so the call is
compiled out of that build — `demo.Enabled` is a constant and the branch is
eliminated, which keeps the promise true by construction rather than by a
setting. Everywhere else it runs with no switch: on a deployment that requires
proof of control the certificate belongs to whoever asked, and a switch they had
to find first would be a gap in a report dressed as a choice.

Both directions are driven. A test under the tag fails if the demonstration
fetches, and a test without it fails if the ordinary build does not — a guard
that refuses everywhere is as wrong as one that refuses nowhere, and the second
failure would be silent, since "revocation was not checked" is a sentence this
project prints honestly in so many other places that nobody would look twice.

*Enforced in:* `internal/crl`, `internal/scan.Scanner.Scan`,
`internal/scan.listStatus`, `internal/policy.GradeStapling`,
`internal/policy.RevocationLine`
*Guarded by:* `TestACertificateOnTheListIsRevoked`,
`TestACertificateNotOnTheListIsGood`,
`TestAListTheIssuerDidNotSignIsRefused`,
`TestAStaleListIsNotAnAnswer`,
`TestAListNotYetInEffectIsNotAnAnswer`,
`TestAnOversizedListIsRefusedRatherThanTruncated`,
`TestASerialIsComparedAsANumber`,
`TestOnlyHTTPAddressesAreFetched`,
`TestCredentialsInADistributionPointAreStripped`,
`TestACertificateNamingNoListSaysSo`,
`TestWithoutTheIssuerThereIsNoAnswer`,
`TestAListThatWasNotServedEstablishesNothing`,
`TestSomethingThatIsNotAListIsNotParsedAsOne`,
`TestNoReasonDescribesTheMachine`,
`TestTheDefaultDiallerRefusesPrivateAddresses`,
`TestAnUnknownListStatusIsNotAnAnswer`,
`TestTheOrdinaryBuildReadsTheRevocationList`,
`TestTheDemonstrationAsksNoAuthorityAnything`,
`TestAListThatNamesTheCertificateIsReported`,
`TestAListThatDoesNotNameTheCertificateSaysAsOfWhen`,
`TestAListThatCouldNotBeReadSaysWhy`,
`TestOneWithdrawalIsOneFinding`,
`TestADeploymentThatReadsNoListIsUnchanged`

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

**Both probes, and the second one was open for two rule sets.** The web check
wrote `hop.Err` straight from the library, so a name that did not resolve
recorded the resolver this machine asked and a destination safedial declined
recorded the address it declined. It was reachable only from the command line,
where the operator reading the report runs the machine described — which is
why it survived. It stops being that the day the check has an address on the
service, and a report is then a reply to a stranger. `classifyProbeError` is
the same rule applied to the other probe, written before that endpoint rather
than after it.

The phrases differ only where the checks differ. This client verifies, which
the TLS probe deliberately does not, so a certificate a browser would refuse
stops a hop here; that is a finding about how the secure address behaves for a
visitor, and it is answered with a phrase rather than the library's text,
which carries a second half-description of a certificate the TLS report
already describes in full.

**A refusal is recognised by what it is, not by how it reads.** The policy
branch is asked before every message test, because its text is the one certain
to carry an address. Nothing today depends on that order — no `ErrBlocked`
message contains a phrase a later branch matches — and that is a fact about
safedial's current wording rather than a property of the function, so the
order is pinned by a test rather than by a comment.

*Enforced in:* `internal/tlsprobe.classifyHandshakeError`,
`internal/webprobe.classifyProbeError`
*Guarded by:* `TestHandshakeErrorsCarryNoInfrastructure`,
`TestReportFromAFailedProbeNamesNoAddress`,
`TestAFailedHopNamesNoInfrastructure`,
`TestAPolicyRefusalIsRecognisedWhateverItSays`

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
same hole in a different place. A deployment that requires proof of control
adds one way through it — the challenge lookup itself failing — which is this
service being unable to ask rather than the domain being unproven, and is why
the two are answered separately (N9).

`not_verified` is driven in the test rather than left defensive, and the
difference from `not_demonstrated` is why. That one needs a build tag, so only
the demonstration's own test can produce it. This one needs nothing but a
configured scope, and a figure nobody drives is a figure nobody notices has
stopped moving. What it says is worth having: people asking about domains they
have not published a record for is either a procedure nobody was told about or
a record that stopped resolving, and no scan count shows either.

**The fact is carried as a field, and the field comes before the entry point
that counts it.** `blocked_destination` was silent on the TLS check until
`tlsprobe.Report.BlockedDestination` existed, because the reason lived in
prose inside a successful report and a count built by matching prose breaks
the first time the prose is improved. `webprobe.Report` carries the same field
for the same reason, and it was given it *before* the web check had an address
on the service — the order N6 argues for, so that an entry point written later
inherits the signal instead of having to remember it.

It is true only where every hop was refused. A name reached on one port and
declined on the other has been measured, and answering that with a refusal
would hide the half that succeeded.

*Enforced in:* `internal/httpapi.Server.refuse`,
`internal/tlsprobe.Report.BlockedDestination`,
`internal/webprobe.Report.BlockedDestination`
*Guarded by:* `TestEveryRefusalCodeCanBeProduced`,
`TestOnlyKnownRefusalCodesAreCounted`,
`TestANameThatResolvesOnlyWhereWeWillNotGoIsRecordedAsBlocked`,
`TestTheWebEndpointCountsABlockedDestination`,
`TestANameReachedOnOnePortIsNotABlockedDestination`,
`TestNoHopsIsNotABlockedDestination`,
`TestOnlyAPolicyRefusalSetsTheBlockedFlag`

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

**The largest of them was unwritten until 2026-09-02: everything measured
here describes one hop.** Every version, every suite, the cipher order and the
key exchange are properties of whatever endpoint answered at the address the
report names. Where a content delivery network, a reverse proxy or a load
balancer terminates TLS, that endpoint is what was measured, and the link from
it to the server behind it cannot be seen from here.

The live scans of 2026-09-01 are the demonstration. `kapitalbank.az` resolved
to `172.66.1.19` and its report carried Cloudflare's fingerprint — a CAA
string character-for-character identical to `cloudflare.com`'s and a cipher
list of the same shape — while stating that *the hybrid post-quantum group
X25519MLKEM768 was accepted*. True of the edge. A reader takes it as a fact
about the bank, and the difference matters precisely for the harvest-now
threat that sentence exists to address, because the classical link may be the
one behind the edge.

It is a standing limit and not a note about the host, for two reasons.
It is true of every scan this program runs, which is what `standing` means;
and deciding which hosts sit behind an intermediary would mean publishing a
claim no handshake establishes. The limit says the honest thing instead —
including that a name resolving to several addresses was measured at one of
them, which is true here whether or not this name did.

It is raised only where something answered. Over a report that reached
nothing it would describe an empty set, and a limit that bounds no measurement
is the kind of sentence that taught readers to skip the limits.

**Nor was it established that one hop meant one machine.** A full scan is
thirteen separate connections and each one resolves the name again, so a
rotating answer set — which is what most recursive resolvers return — can hand
successive handshakes to different servers. The report recorded the address of
the newest version that answered, printed it at the top, and presented every
version, suite and certificate below as though one machine had produced them
all. No row was false. The report as a whole made a claim it had never
checked, and had thrown away the evidence that would have settled it: four of
the five handshake call sites discarded the address they reached.

Every handshake now records it, into a set held for the length of one probe —
never on the `Prober`, which serves every scan the service runs. Where the set
holds more than one entry the report says so and names them. This is a note
about the host rather than a limit of the method, because it is established
here: these are the addresses the handshakes reached, and this scan knows
whether there was more than one.

**And "trusted" is one store's opinion.** A chain verifies against the root
store of the machine that ran the scan. Chrome, Apple and Microsoft each ship
their own, remove authorities on their own timetables, and a packaged store
lags the programme it is built from — so a chain trusted here can fail in a
browser, and one untrusted here can be accepted. The report said *the* trust
store, with the definite article, as though there were one. It is a standing
limit, raised wherever a chain was checked, because a reader of `untrusted`
needs the caveat as much as a reader of `trusted`.

*Enforced in:* `internal/tlsprobe`, the `Notes` field
*Guarded by:* `TestSupportedVersionsCarryTheCoverageNote`,
`TestDescribeTransparencySeparatesTheFourSituations`,
`TestEveryNoteInAReportCarriesAKind`,
`TestAReportSaysItMeasuredOneHop`,
`TestAReportThatReachedNothingClaimsNoHop`,
`TestAReportNamesTheAddressesItReached`,
`TestAScanThatReachedTwoMachinesSaysSo`,
`TestTheAddressesReachedAreRecordedOnceEach`,
`TestTheReportSaysWhoseRootStoreDecided`

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

**The store a chain is judged against is the store this program checked.** The
same rule read one layer down, and it was broken in the layer nobody looked
at. `x509.Verify` with a nil `Roots` does not mean "the system pool"; it means
*decide for yourself*, and on Windows and macOS deciding hands the whole
question to the platform verifier — a different store, reading neither the
pool `denyfirstd` reads when it starts nor `SSL_CERT_FILE`. So the service
satisfied itself that its trust store was not empty and then judged every
chain against something else, on the two platforms self-hosting is most likely
to run on. It refused to start on a machine with no store and would have
reported chains as trusted on one it never consulted.

The pool is a parameter now, `denyfirstd` hands the scanner the pool it
checked, and nothing leaves `Roots` nil. A non-nil `Roots` takes the pure-Go
path everywhere, so one store decides on every platform — which is what this
invariant asks for and what the nil was quietly preventing.

The symptom was visible for months and read as something else. Two tests in
`internal/certinfo` failed on Windows and macOS from the day they were
written, because the fixture installed its private authority through
`SSL_CERT_FILE` and only Go's unix root loader reads it. That looked like a
fixture that did not port. It was the program measuring against a store it had
never looked at, and the fixture was the only thing saying so. The tests pass
the pool now, which is what the program does, so they exercise the real path
rather than a second one arranged for them — and the package runs on every
platform.

**A store that cannot be read is a fact about this machine.** It is said in
words rather than reported as an untrusted chain, which would be a finding
about somebody else's certificate produced by a local failure (R4). The pool
returned in that case is empty rather than nil, because nil would send the
verification back to the platform — and on the machine whose store could not
be read, that path reports chains as trusted.

**And the same hole was in the other check.** `internal/certinfo` was fixed on
2026-09-10; `internal/webprobe` set no `TLSClientConfig` at all, so every web
chain was verified with a nil `RootCAs` — which reaches `x509.Verify` as a nil
`Roots` and hands the question to the platform. A service that read its own
store, refused to start without one, and passed it to the TLS scanner was
judging half its chains against something it had never looked at.

Here it is worse than a wrong grade. A certificate the deciding store cannot
verify is a handshake that **fails**, and a failed handshake on both ports reads
as a site that is not served over HTTPS. The report would not say "trusted" when
it should not; it would say the server does not offer HTTPS at all.

Which is why the fix carries a second half. `truststore.Resolve` answers an
unreadable store with an **empty** pool — safe, and unusable — so closing the
first defect would have opened a worse one: every chain failing, with nothing
saying why. `webprobe.Report.TrustStoreUnreadable` carries the fact,
`webscan.Grade` turns it into an unsettled note, and the sentence is
`policy.TrustStoreUnreadable()` because both checks say it and two copies of a
claim about whose store decided the word "trusted" are two copies that drift
(R16).

**The rule itself is `internal/truststore`, and that is the point of the
package.** It holds one decision — nil means the system store, loaded
explicitly; a failure means an empty pool and never nil — and it exists because
that decision was about to be written a second time. Each check keeps a
`resolveRoots` variable pointing at it, so a test can make the failure happen on
the machine no test runs on, and neither keeps a copy of the rule.

**Setting a `tls.Config` moves responsibility for everything it does not say.**
What is deliberately absent is asserted rather than assumed: no
`InsecureSkipVerify`; no `ServerName`, which would be checked against the
certificate of every host a redirect moved on to; no `ClientSessionCache`, which
is shared across hosts and would resume somebody else's session; and no
`MinVersion` or `MaxVersion`, because naming one would move a *measurement* — a
host reachable only over an older protocol would begin to be reported as not
reachable at all.

**A check that cannot run on a platform is a check that does not run there, and
this rule is about that too.** The CAA lookup said *not checked* on every
Windows machine from the day it was written until 2026-09-11. Nothing was
wrong with the check: `internal/dnsclient` found the resolver by reading
`/etc/resolv.conf`, Windows has no such file, and the honest failure was
reported honestly. So the same scan of the same host produced a complete report
on Linux and a report missing a whole row on Windows — which is precisely what
this invariant forbids, arriving as a platform the code did not have a path for
rather than as a wrong answer.

The comment saying so had been there the whole time. Written down as a known
limit, a missing platform reads as a decision; it was not one, and nothing
ever came back to it. **An honest note about a gap is not a substitute for
closing it**, and "the report says the check did not happen" is the floor
rather than the answer.

Two things came out of fixing it, and the second is the one worth keeping. The
resolver is now found per platform — resolv.conf on unix, the registry on
Windows — which was the obvious half. The other half is that **one resolver is
not a machine's answer**: the first attempt read the Windows registry
correctly, returned the primary resolver of the live adapter, and the check
still said *not checked*, because that resolver belongs to a virtual adapter
and does not answer. Windows had a second one configured for exactly that case
and was using it for everything else. So every configured resolver is tried in
order, the one that answered is asked first next time — a CAA walk makes up to
six queries and must not pay a dead resolver's timeout on each — and the same
change closes the same latent defect on unix, where `resolv.conf` lists several
for the same reason and only the first was read.

**And a platform's file is compiled nowhere, so it is vetted everywhere.** `go
vet ./...` on Linux does not read a file behind `//go:build windows`; it is not
merely unvetted, it is never compiled, so a syntax error in it passes every
gate and fails in `scripts/build.sh` on a release evening. CI now vets `linux`,
`darwin` and `windows`. vet type-checks rather than links, so it costs seconds
and needs no cross toolchain.

*Enforced in:* `internal/certinfo.chainComplete`,
`internal/certinfo.resolveRoots`, `internal/scan.Scanner.Roots`,
`cmd/denyfirstd`, `internal/truststore`, `internal/webprobe.Prober.Roots`,
`internal/webscan.Scanner.Roots`, `internal/policy.TrustStoreUnreadable`,
`internal/dnsclient` (`resolver_unix.go`, `resolver_windows.go`, `Client.ask`),
`.github/workflows/ci.yml`
*Guarded by:* `TestMissingIssuerIsAnIncompleteChain`,
`TestPresentIssuerIsNotAnIncompleteChain`,
`TestTheRootsPassedInAreTheOnesThatDecide`,
`TestANilPoolBecomesTheSystemPoolRatherThanThePlatformVerifier`,
`TestAPoolPassedInIsNotReplaced`,
`TestAnUnreadableStoreIsNotReportedAsAnUntrustedServer`,
`TestTheTestRootIsTheStoreAnalyseUses`,
`TestTheScannersTrustStoreIsWhatJudgesTheChain`,
`TestAnEmptyTrustStoreStopsTheServiceStarting`,
`TestADeadResolverIsFollowedByTheNextOne`,
`TestTheResolverThatAnsweredIsAskedFirstNextTime`,
`TestEveryResolverFailingKeepsTheFirstReason`,
`TestAnEmptyResolverSetSaysSo`,
`TestAConfiguredResolverIsTheOnlyOneAsked`,
`TestEveryNameserverIsRead`, `TestAnUnusableNameserverIsSkipped`,
`TestTheNameserverListIsBounded`,
`TestAFileWithNoNameserverIsNoResolver`,
`TestAMissingResolvConfIsNoResolver`,
`TestANameserverListIsSplitHoweverItWasWritten`,
`TestARegistryStringIsDecoded`,
`TestTheMachineReportsUsableResolvers`,
`TestTheResolverListDropsWhatCannotBeAsked`,
`TestTheResolverListIsBounded`,
`TestTheResolverFlagReachesTheScanner`,
`TestNoResolverFlagLeavesTheMachinesOwnConfiguration`,
`TestEveryReleasedPlatformIsVetted`,
`TestAnUnreadableStoreResolvesToAnEmptyPoolRatherThanNil`,
`TestTheRootsPassedInAreWhatVerifiesAWebChain`,
`TestAStoreWithoutTheAuthorityRefusesTheChain`,
`TestAnUnreadableStoreIsCarriedIntoTheReport`,
`TestAReadableStoreIsNotReportedAsUnreadable`,
`TestTheClientCarriesNoWeakeningTLSSetting`,
`TestTheScannersTrustStoreDecidesTheHandshake`,
`TestAProberWithItsOwnTrustStoreKeepsIt`,
`TestAnUnreadableStoreIsSaidInWordsRatherThanAsAnUnreachableSite`,
`TestAReadableStoreAddsNoNote`,
`TestOneSentenceSaysTheStoreCouldNotBeRead`,
`TestTheConstructorGivesEveryCheckTheSameTrustStore`,
`TestReplacingTheWebScannerCannotDropTheTrustStore`

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

### R14a — A chain is graded, not only checked for trust

Until 2026-09-02 all twenty-four certificate rules looked at the certificate
served for the host. The chain was checked for trust — does it reach a root —
and never for strength, so a report could say

```
Chain   4 certificates, trusted
```

beside a `strong` verdict while three of those four had been graded by
nothing. An intermediate signed with SHA-1, or holding a 1024-bit key, passed
in silence.

It matters more on an issuer than on a leaf. A forged leaf impersonates the
names inside it; a forged intermediate issues certificates for **any** name,
accepted by every client that trusts the chain. That is R5 applied upwards: a
chain is only as sound as the weakest certificate a client must accept on the
way to a root.

What is not graded is as deliberate as what is. **Names** are a question about
a certificate presented for a name, and an issuer is not presented for one.
**Self-signature** is what a root is. **Validity length** is measured in
decades for an authority by design. **Being an authority** and holding
`keyCertSign` are required of an issuer — the exact inverse of the leaf rules.

**And the root is not graded at all.** A root is trusted because the client
already holds a copy, not because of the signature it carries; no client
verifies that signature, and one that did would be asking a certificate to
vouch for itself. Grading it would raise an alarm about a risk nobody runs,
and roots predating SHA-256 sit in every store today doing no harm. Any
self-signed certificate in the chain is skipped, which is how a client treats
it — and where the server sent one, the report says so and says why.

The identifiers are `chain.` rather than `cert.` because a pipeline filtering
on `cert.signature-sha1` had already fixed that identifier's meaning. A new
identifier is additive; a widened one is a silent change.

The rules are written twice — once for the leaf, once for an issuer — because
the consequence differs and the sentences have to say so. What must not differ
is *when* they fire, so a test drives thirteen key and signature combinations
through both graders and fails if either fires where the other does not.

**The tests needed a trust store before they could see any of this.** A root
generated in a test is in no store, so every chain these tests built failed
verification and every report came out `insecure` from `cert.chain-untrusted`
whatever else was true. An issuer's contribution to the verdict was invisible,
and a sabotage that replaced the fold with the leaf's own verdict passed the
whole suite.

`internal/certinfo`'s `TestMain` now writes one root to a PEM and points
`SSL_CERT_FILE` and `SSL_CERT_DIR` at it before anything verifies — the system
pool is built once per process, so that is the only moment early enough. A
chain built the ordinary way verifies; a test that wants one that does not
calls `newUntrustedRoot` and says so by calling it. Both variables are set
because Go consults them separately and either one alone lets the machine's
own 150-odd authorities back in, which a test asserts by counting the pool.

An impeccable leaf under an issuer expiring in ten days is the shape that was
unreachable before: the chain verifies, the leaf grades `strong`, the report
grades `weak`. The issuer's fault is deliberately one Go's verifier tolerates
— a SHA-1 issuer would break the chain and put the leaf back at `insecure`,
which is the blind spot again.

**What an issuer is not allowed to do is reported, and only where it says.**
Name constraints bound which names an authority may issue for; a path length
bounds how many authorities it may create beneath itself. Both matter for one
reason: an unconstrained intermediate whose key is stolen issues certificates
for any name on the internet, and a constrained one issues for a handful of
domains and nothing else.

Only the positive case is reported. An issuer with no constraints produces no
sentence, and that is not the kind of silence the rest of this document closes.
The silences that mattered — one hop, one address, one root store — changed
what a claim covered. This one does not: an unconstrained issuer is the
ordinary state of nearly every certificate on the internet, and saying so on
every report would be true, add nothing, and teach a reader to skip the block
it sits in. That is how the old *What this did not measure* heading stopped
being read. It is also, for once, a report with something good to say.

A root's constraints are skipped for the same reason its signature is not
graded: the root a client uses is the copy in its own store, not the one the
server sent, and the two need not carry the same extensions.

*Enforced in:* `internal/policy/chain.go`, `internal/certinfo.worstAcross`,
`internal/certinfo.issuerConstraints`
*Guarded by:* `TestASoundIssuerRaisesNothing`, `TestWhatAnIssuerIsGradedOn`,
`TestBothGradersFireOnTheSameCryptography`,
`TestAnIssuerIsNotGradedOnWhatItIsNot`, `TestAWeakIssuerReachesTheVerdict`,
`TestARootIsNotGradedAndTheReportSaysWhy`,
`TestAnIssuerSubjectCannotRewriteTheReport`,
`TestTheVerdictIsTheWorstAcrossTheChain`,
`TestAFindingAboutAnIssuerReachesTheFindings`,
`TestASoundLeafTakesItsIssuersVerdict`, `TestTheTestRootIsTheStoreAnalyseUses`,
`TestAConstrainedIssuerIsDescribed`, `TestAnUnconstrainedIssuerSaysNothing`,
`TestARootsConstraintsAreNotReported`,
`TestAConstraintCannotRewriteTheReport`

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
shortcomings it reads as though it were one of them. They are declared once
in `internal/policy/standing.go`; `/method` ranges over that declaration and
`denyfirst-scan -limits` prints it, so the page cannot fall out of step with
the code and somebody offline is not sent to a website.

Nothing says how many there are. Both faces count the list at render time,
because a sentence naming a number is a sentence that goes stale the day
another limit is written — which happened on 2026-09-02, when the first-hop
limit made four into five.

Moving them is only honest if the report still says they exist. It gives the
count and names both places to read them, and a test fails if it stops doing
either — or if a standing sentence is written inline rather than added to the
declaration, which would leave a report counting the limits it points at while
carrying one more that nothing explains.

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

**Since 2026-09-02 the printed name is assembled here rather than by the
standard library**, so it is worth saying which rule does which job. RFC 4514
escaping is about the *grammar of a name*: a comma inside a value is what
separates two attributes outside one, so an organisation called `Bank, Inc.`
has to be escaped or the name a reader sees is not the name the certificate
holds. `sanitise` is about the *display*, and it runs afterwards, over the
finished string, exactly as it did when Go built it. Neither substitutes for
the other and the order is not interchangeable.

The reason for assembling it here is that Go renders an attribute type it has
no name for as the dotted identifier and the DER bytes in hexadecimal. On an
extended-validation certificate that is three attributes —
`1.3.6.1.4.1.311.60.2.1.2=#130844656c6177617265` carries the word *Delaware*
and shows none of it — and they are precisely the attributes extended
validation exists to carry. Go had already read the values; only the rendering
discarded them.

The arrangement is Go's, deliberately: same attribute order, same separators,
same escaping. A certificate carrying only attributes Go names renders
character-for-character as it always has, checked against Go's own output as
the oracle on a name that came off the wire — a hand-built `pkix.Name` has an
empty `Names` field and never exercises the path where the two could diverge,
which is how the first version of that check passed a change that printed
`CN`, `O` and `C` twice.

*Enforced in:* `internal/certinfo.sanitise`, applied by `trimmer.text`;
`internal/certinfo.mixedScriptNote`, `internal/certinfo.confusableScripts`;
`internal/certinfo.distinguishedName`
*Guarded by:* `TestControlCharactersInCertificateFieldsAreNeutralised`,
`TestC1ControlsAreNeutralisedToo`, `TestTrimmingCutsOnARuneBoundary`,
`TestNothingCanRewriteHowTheReportReads`, `TestANameInTwoAlphabetsIsSaid`,
`TestALookalikeNameIsNotRewritten`,
`TestAnOrdinaryNameRendersExactlyAsItDidBefore`,
`TestAParsedOrdinaryNameRendersExactlyAsItDidBefore`,
`TestAnExtendedValidationNameIsReadable`,
`TestAnExtendedValidationSubjectReachesTheReport`,
`TestAValueThatLooksLikeTheGrammarIsEscaped`

### R20 — A value does not repeat the heading it is printed under

Every suite in a report is printed under the protocol version it was accepted
at: the page groups by version, the command line groups by version, and the
JSON nests the suites inside the version. The key exchange for a TLS 1.3 suite
read `ephemeral (TLS 1.3)`, so a table headed **TLS 1.3** printed the words
"TLS 1.3" again on every one of its rows.

The parenthesis looks like the reason for the value and is not. It is the
heading a second time. Where the ephemerality actually comes from — the suite
name in TLS 1.3 carries an AEAD and a hash and nothing else, the group is
chosen in an extension, and RFC 9846 removed static exchange from the protocol
— is a paragraph, and it belongs on `/method`, not in a parenthesis repeated
six times down a column.

Enforced where the name is made rather than in either of the two places it is
shown, so both faces agree without either being asked to. Checked across every
suite the standard library names, plus the two RFC 9150 suites it does not,
plus a name it has no entry for.

A second rule falls out of the same fact: every TLS 1.3 suite has to report the
same key exchange, because none of them measures one. A row that said
something different would be claiming a measurement nobody made.

*Enforced in:* `internal/policy.DescribeCipher`
*Guarded by:* `TestACipherDescriptionDoesNotRepeatItsProtocolVersion`,
`TestEveryTLS13SuiteReportsTheSameKeyExchange`

---

### R21 — Where no document sets a threshold, the measurement is reported and not graded

A verdict here rests on something a reader can open. Where nothing publishes a
line, the honest output is the number and what it means, not a number this
project made up and then failed a server for missing.

`denyfirst-web-v1` leans on this three times in its first ten rules, and each
one was a rule that could have been written and was not:

- **The length of an HSTS `max-age`.** No standards body publishes a minimum,
  and OWASP's cheat sheet explicitly recommends a short one during a rollout.
  So the value is described — in years or days, with what a browser does when
  it lapses — and the one-year figure appears only as what it is: the entry
  requirement for one browser programme's list.
- **The absence of `includeSubDomains`.** A host with nothing beneath it needs
  no subdomain clause, and a scan of one host cannot see what is beneath it.
- **A temporary redirect from the plaintext address.** A 302 to the secure
  address works. It is described, because a browser may repeat the cleartext
  request where a permanent one would not, but it is not a fault on its own.

This is R6 and R9 pointed at a new rule set rather than a new idea: R6 says
correct configuration is not penalised, R9 says issuance policy is reported
and not graded, and both exist because a scanner that invents thresholds
teaches its readers to ignore it. The failure mode is specific and cheap to
reach: a threshold with no source behind it is one nobody can argue with,
which means nobody can correct it either, and it survives into a report that
tells somebody their correct decision is a fault.

Where a rule *does* fire, the opposite obligation holds: it cites a document,
and a test refuses a finding that cites nothing.

**The test is not whether a document says MUST.** Every case above is one a
correctly configured server legitimately produces: a host with nothing beneath
it needs no subdomain clause, a rollout wants a short `max-age`, and a 302 to
the secure address works. That is the line — *can a correct server look like
this?* — and it is not the same as asking whether some specification uses the
word.

The cookie rules were written against it, because cookies are where the
temptation is strongest: there is a large body of advice about them and almost
none of it is a line anybody published. What is graded is the set of cases
where **a browser does not store the cookie at all** — a `__Host-` prefix whose
three conditions are not met, `SameSite=None` without `Secure`, and a cookie
set over TLS without `Secure`, which a browser then sends in the clear. Those
are not opinions about configuration; they are what happens next, and a site
that has one is usually the last to know, because the response looks exactly as
intended and the failure appears somewhere else.

What is reported instead is the advice. `HttpOnly` is missing from a great many
cookies that are meant to be read by script — a CSRF token, a locale, a consent
flag — and this check cannot tell which it is looking at, because it never
records a value. Grading that would fail correct servers for a rule nobody
wrote, which is exactly the failure this invariant is named for.

*Enforced in:* `internal/policy/web.go`, `internal/policy/cookies.go`,
`internal/policy/headers.go`
*Guarded by:* `TestAShortMaxAgeIsDescribedAndNotGraded`,
`TestIncludeSubDomainsIsDescribedAndNotGraded`,
`TestATemporaryRedirectIsDescribedNotGraded`,
`TestAPermanentRedirectIsNotCalledTemporary`,
`TestNothingOnPortEightyIsObservedRatherThanGraded`,
`TestEveryWebFindingIsUsableOnItsOwn`,
`TestAdviceIsReportedAndNotGraded`,
`TestACookieABrowserWillNotStoreIsGraded`,
`TestACorrectlySetCookieIsNotGraded`,
`TestACookieSetOverPlaintextIsNotChargedForMissingSecure`,
`TestNoCookiesProducesNothing`,
`TestOneFaultAcrossManyCookiesIsOneFinding`,
`TestEveryCookieFindingCitesSomethingAndNamesItsRuleSet`,
`TestACookieNameIsCarriedThroughAsText`,
`TestTheCookieRulesReachAGradedReport`,
`TestACookieIsNotReadFromAHopThatFailed`,
`TestACookieCarriesTheTransportItWasSetOn`,
`TestCorsHeadersThatContradictEachOtherAreGraded`,
`TestEitherHalfOfTheCorsPairAloneIsNotGraded`,
`TestTheRecommendedHeadersAreReportedAndNotGraded`,
`TestNosniffIsReportedAndNotGraded`,
`TestAContentSecurityPolicySupersedesTheOlderFramingHeader`,
`TestAReportOnlyPolicyIsDescribedAsNotYetEnforcing`,
`TestAHostThatAnsweredNothingIsNotDescribedAsSendingNoHeaders`,
`TestASiteThatSendsEverythingIsToldNothing`,
`TestTheReportedListIsStable`,
`TestTheHeaderRulesReachAGradedReport`,
`TestTheHeadersReadAreTheOnesOnTheResponseAVisitorLandsOn`

---

### R22 — One rule set grades one check, and every verdict names its own

A number on its own stopped meaning one thing the moment a second check
existed, which it now does. `denyfirst-tls-v6` grades a handshake and a
certificate; `denyfirst-web-v1` grades an HTTP response, which most of the
ports this project dials do not have.

**The identifier follows the value.** `policy.Version` beside
`policy.WebVersion` reads as *the* version and the web one, which is exactly
the confusion renaming the value to `denyfirst-tls-v6` in v0.13.0 was meant to
end. It is `policy.TLSVersion` now. No rule moved with either rename.

**Each rule set has its own standing limits.** What a TLS scan cannot
establish and what a header check cannot establish are different lists, and
one list read under both headings is a list nobody reads. A web limit must not
even be mistakable for a TLS one: `IsStandingLimit` answers for the TLS set,
and a test fails if it answers true for a web limit, because a report could
then carry it under the wrong heading with every existing guard still green.

**Both rule sets appear on the change log.** A second rule set that can move
without a record is the first one's problem repeated.

**The counters obey it too, and they are published.** `Snapshot` carried one
verdict breakdown, so a second check counted into it would have produced a
`strong` adding a handshake to an HTTP response — a figure describing nothing
anybody can check, on the one endpoint this project publishes precisely
because it can be checked. Each check has its own block naming its own rule
set, keyed on the check rather than on the rule set so that a version bump
does not restart a counter under a new name.

**Nothing already published moved.** The fields at the top of a `Snapshot` are
the TLS check's, spelled the same way and counting the same thing, and the
`tls` block repeats them. A field that keeps its name and changes its meaning
is the change nobody notices until a graph has been wrong for a month, and it
would survive a rollback as well: `cmd/denyfirstd` reads the file with a plain
`json.Unmarshal`, so an older binary ignores the new field — and what it then
reads at the top has to still be one check's figures rather than a total with
another check's scans folded in.

**A key appears only once that check has been counted**, because a block of
zeros for a check this build cannot run is the silence A7 is about. Keys are
filtered on restore exactly as the refusal codes are, and the published map is
cloned: the freeze in P-series that keeps a pollable counter from being a
clock is free for an integer and is not free for a map.

*Enforced in:* `internal/policy` (`TLSVersion`, `WebVersion`,
`WebStandingLimits`); `internal/httpapi` (`checkNames`, `CheckCounts`,
`Snapshot.Checks`)
*Guarded by:* `TestTheWebRuleSetIsNamedForItsCheck`, `TestTheWebLimitsAreItsOwn`,
`TestEveryWebFindingIsUsableOnItsOwn`, `TestTheChangeLogCoversTheCurrentPolicy`,
`TestThePublishedFieldsKeepTheirNamesAndTheirMeaning`,
`TestTheTopLevelFiguresAreTheTLSCheck`,
`TestEveryCheckBlockNamesItsOwnRuleSet`,
`TestAWebScanDoesNotMoveTheTLSFigures`, `TestACheckWithNoScansHasNoBlock`,
`TestOnlyKnownChecksAreCounted`, `TestEveryCountedCheckCanOccur`,
`TestAFileWithoutCheckBlocksRestoresIntoTheTLSBlock`,
`TestARollbackReadsTheTLSFiguresAndIgnoresTheRest`,
`TestRestoreFiltersUnknownChecks`,
`TestARestoredBlockDoesNotCarryTheOldRuleSetName`,
`TestSnapshotEqualityCoversTheCheckBlocks`,
`TestTheDailyFigureResetsForEveryCheck`,
`TestThePublishedCheckFiguresStandStillToo`,
`TestAWebScanIsCountedAgainstItsOwnCheck`,
`TestTheWebEndpointAnswersAReport`

---

### R23 — The policy read is the one a browser would hold

A browser applies `Strict-Transport-Security` from **every** response that
arrives over a secure transport, and discards it from every response that
arrives any other way. A chain of three redirects therefore has three chances
to set a policy, a later one replaces an earlier one, and the response a
visitor finally lands on may set none at all while the browser still holds one.

So the value graded is **the last one carried by a hop that was made over
TLS**. Reading the last hop describes a policy no browser holds the moment a
site downgrades to plaintext at the end of its chain; reading the first
describes one a later hop replaced. Both are wrong in the same way: they are
answers to a question about the server that were actually decided by which
line of code was easiest to write.

**A hop that failed is not a response with no headers.** A refused connection
says nothing about what a server declares, and the difference decides a
verdict rather than a detail: a host answering `200` in the clear is insecure,
and a host with nothing listening on port 80 is the safest arrangement there
is. One boolean separates them.

**A policy sent only over plaintext is looked for on purpose.** It is a common
arrangement and one nothing else in a report would show — the site is
configured and unprotected at the same time — so the plaintext chain is read
for the header the rules then grade as having no effect.

**There is one copy of the grading.** `Grade` is exported so that a test with
no network calls it rather than reimplementing it; a reimplementation keeps
passing after the original stops doing what it copied, which is the shape of
every drifted second copy this repository has caught.

**Silence is not a verdict, in either direction.** This is the same rule read
twice, and `denyfirst-web-v1` broke it both ways on the day it shipped.

A sound arrangement was reported as `ungraded`, which means *nothing was
established* and is what an unreachable host gets. The check had established a
great deal, and on a command line whose exit status is the whole product the
two came out as the same number — so a pipeline gated on it failed on every
host that passed. Where the secure address answered over TLS and nothing was
wrong, the verdict is `strong`.

And a host that answered nothing at all was graded `weak` for declaring no
policy, which is a claim about a server this program never spoke to: an empty
list of headers is what both a silent host and a bare response produce, so the
rules are told which it was rather than left to guess. Both directions are R4
and R17 applied to a rule set that was written the day before them.

*Enforced in:* `internal/webscan` (`securePolicy`, `plaintextPolicy`, `hops`,
`answered`, `Grade`); `internal/policy/web.go` (`GradeReach`, `GradeHSTS`)
*Guarded by:* `TestThePolicyReadIsTheOneABrowserWouldHold`,
`TestAPolicySentOverPlaintextIsFoundSoItCanBeReported`,
`TestAFailedHopIsNotAResponseWithNoHeaders`,
`TestAWholeScanIsGradedAndCarriesItsEvidence`,
`TestACorrectlyReachedSiteIsStrongAndNotSilent`,
`TestAHostThatAnsweredNothingIsNotGradedForItsPolicy`,
`TestAChainEndingOnPlaintextIsNeverSound`,
`TestEveryReportCarriesTheLimitsOfTheMethod`,
`TestNoTLSLimitIsCarriedByAWebReport`,
`TestTheReportSerialisesWithoutItsSecrets`,
`TestScanAndGradeAgreeOnTheHost`,
`TestATargetThatIsNotAHostnameIsRefusedBeforeAnythingIsAttempted`

---

## The page

The frontend had no entry here while it was the only part of this project a
visitor actually runs. The properties below carry it, all load-bearing, and
each undoable in one line by somebody with a good reason.

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

### W3 — A table with the same columns is drawn with the same columns

The cipher suites are printed one table per protocol version, one under
another, with the same four headings each time. Each table used to size its
own columns to its own contents, which is what a browser does when nothing
tells it otherwise. Measured in a browser on a live report, "Key exchange"
began 92 pixels further right under TLS 1.2 than under TLS 1.3, and "Cipher"
68 pixels further left. Every row was correct. A table exists so that a reader
can run an eye down a column, and down two of these nobody could.

The geometry is declared on a `<colgroup>` and the layout is fixed, so the
widths are read before any row is. The widths are written in `ch` on the
`<col>` elements rather than on the header cells, because a fixed layout takes
its geometry from the columns first and because the header is set in a smaller
font than the body — a width in `ch` on a `<th>` would be measured in the
wrong font. Each column is given its own worst case: the longest suite name
the standard library can print is 45 characters, the longest key exchange is
`ephemeral (TLS 1.3)`, the longest cipher is `ChaCha20-Poly1305`, the longest
grade is `insecure`.

A suite name is never broken. The column previously carried
`word-break: break-all` so that a long name would fit a narrow screen; it fits
by arriving as `TLS_ECDHE_RSA_W` / `ITH_AES_128_GCM` / `_SHA256`, and the name
is the finding. A reader copying that by hand writes down a suite that does
not exist. The table is put in a container that scrolls instead, and the
container is shaded at whichever edge it can still travel towards — without
that, a reader on a phone sees Grade and Suite and never learns that the key
exchange and the mode of encryption were recorded at all. The shade is a
colour token defined in both schemes, because a black shadow on a dark page is
no shadow.

Paper does not scroll, so the fix for the screen is a way to lose data on a
printed page. Under `@media print` the container stops scrolling, the table
gives up its minimum width, the columns are given shares of the sheet so that
the two tables still agree with each other, and the identifier is allowed to
wrap — the one place where breaking a name is better than dropping it.

Measured, not inferred: 380, 794 and 1000 pixels wide, in both colour schemes,
with the longest value in every column present. In each, the two tables' four
headings sit at identical x positions, no name wraps, no cell is clipped, and
the page itself never scrolls sideways.

*Enforced in:* `internal/web/assets/app.js`, `internal/web/assets/style.css`
*Guarded by:* `TestEveryCipherTableIsGivenTheSameColumns`,
`TestASuiteNameIsNeverBrokenOnScreen`,
`TestTheCipherTableScrollsInsideItsOwnContainer`,
`TestNothingIsLostOffTheEdgeOnPaper`,
`TestTheClassesTheScriptAddsAreStyled`

### W4 — A shipped asset does not carry instructions for editing itself

Two comments reading `Append this to internal/web/assets/style.css. Nothing
above it changes.` and `Replace the ".prose" block near the end of style.css
with this` were served to every visitor from the stylesheet they describe.
They were patch instructions written for a person applying a change, left in
the file the change was applied to.

A browser ignores them and no reader is harmed. They are still a file saying
something untrue about itself on a site whose entire claim is that it does not
say what it cannot support, and the same slip in a file that is executed
rather than parsed for style would not have been cosmetic.

*Enforced in:* `internal/web/assets/style.css`, `internal/web/assets/app.js`
*Guarded by:* `TestTheAssetsDoNotCarryInstructionsForEditingThemselves`

### W5 — A colour text is set in is legible on the paper it is set on

The stylesheet opens by saying that what could not be measured is set in the
same weight as what could, "because a reader who is not told what was skipped
will read silence as a clean result". The weight was equalised. The colour was
not.

Measured in a browser across a full report and both prose pages, in both
colour schemes: the faint ink came to **3.11:1** against paper in the light
scheme and 3.92:1 against the sunk paper in the dark one, against the 4.5:1 a
reader with ordinary vision needs at the sizes this page uses — and nothing on
the page is large enough for the 3:1 allowance. What that ink carries is not
decoration: the coverage line, the count of what was observed and not graded,
the pointer to the standing limits, the dash that stands for a value there
was none of, and the words "not measured". The amber of a weak verdict came to
3.93:1 against paper and **3.60:1** against the sunk paper a finding is drawn
on — below the threshold on the one word the whole report exists to deliver.

Both were deepened until they clear it and no further, keeping hue and
saturation, so the palette still reads as print rather than as an alarm panel:
`--ink-faint` `#8a8f98` → `#676c75` and `--weak` `#a6740c` → `#8f640a` in the
light scheme, `--ink-faint` `#767b84` → `#82878f` in the dark. The ink
hierarchy survives it — 15.6 : 7.2 : 4.6 against the worse of the two paper
surfaces.

Every colour used for text is checked against **both** paper surfaces in both
schemes, because a colour legible on one and not the other is a colour waiting
for the day somebody moves the element. The list of colours is read out of the
stylesheet rather than written down, so one added later is checked without
anybody remembering to add it. The one inversion on the page — the submit
button, which prints paper on ink — is checked against ink instead.

`--rule` is excluded and separately forbidden from being used for text: a
hairline between rows that met the text threshold would be a bar, not a
hairline. The exclusion is itself checked, so it cannot quietly protect a
colour that would now pass anyway.

*Enforced in:* `internal/web/assets/style.css`
*Guarded by:* `TestEveryColourTextIsSetInIsLegible`,
`TestTheRuleColourIsNeverUsedForText`, `TestTheContrastArithmeticIsRight`

### W6 — A state is said in words and in colour, never by fading

The submit button carried `opacity: 0.55` while a scan ran. Opacity fades an
element's text and its own background together against the page, so the label
and the ink under it lose contrast at the same rate: measured in a browser,
**2.29:1** in the light scheme and **2.54:1** in the dark — below even the 3:1
a non-text control needs, let alone the 4.5:1 for the word on it.

That is the only thing the page shows for the several seconds a scan takes,
and a scan is thirteen to fifty handshakes, each a real connection to
somebody's server. A visitor who cannot tell whether anything is happening
presses the button again, and the cost of that is paid by the scanned host,
not by us. Reading the word "Checking" is the entire purpose of the state.

The ink is softened instead — `--ink-soft` behind the same paper-coloured
label, 7.9:1 — which says the same thing and can be read while it says it.
The label already changes from "Check" to "Checking"; the colour now agrees
with it rather than arguing.

Opacity below 1 is allowed inside `@keyframes`, where it is a transition
rather than a resting state and nobody is asked to read anything mid-fade.
Everywhere else it is refused outright, because the next state somebody fades
will be faded for the same reason this one was.

*Enforced in:* `internal/web/assets/style.css`
*Guarded by:* `TestNoRestingStateIsFadedOut`, `TestTheWorkingStateIsLegible`

### W7 — The furniture is the right size and there is not too much of it

Three measurements on the parts of the page that are not the report.

**The footer wrapped with room to spare.** `.colophon p` carried
`max-width: var(--measure)` — 34rem, the width running text can be read at —
and the row of links is written as a paragraph, so it inherited it. The five
links come to 677 pixels against a 578 pixel measure, and they broke onto a
second line inside a footer 884 pixels wide. A measure is a constraint on
reading sentences; applied to a row of links it is only a narrower box. The
measure now excludes the row at the selector rather than being overridden
below it, because `.colophon p` beats a bare `.colophon-links` on specificity
whatever the order — an override there has to be written stronger than it
looks, and the next reader would not know why. The row still wraps on a phone,
where there is no width at which five links fit and wrapping is the answer.

**Two notices stood under one field.** The link to what a scan sends had a
paragraph to itself beneath the paragraph about the terms. A page papered with
notices is a page whose notices are skipped, and the skipping generalises to
the next one. The link joined the sentence above it — the sentence a reader is
already reading before pressing the button, which already carried the link to
the terms. Nothing was removed: the home page still links `/privacy#scans`,
and the test that has always required it still passes.

It is also the better target there. A link alone in a paragraph is a control
16 pixels high, under the 24 a pointer needs; the same link inside a sentence
is an inline link, exempt because the sentence around it is what makes it
findable.

**The mark cleared the floor by accident.** The wordmark measures 106 by 26
pixels, which passes the 24 a pointer needs — by two pixels, and because 26 is
what a 1rem line box happens to be. A font-size trimmed by a tenth of a rem
one afternoon would have taken the target under the floor and changed nothing
anybody would notice. `min-height` says it instead: it costs nothing today and
holds on the day the type shrinks. The `inline-block` is what lets a height
apply at all, and an inline-block takes its baseline from its last line box,
so the mark still sits on the same baseline as the note beside it — measured
before and after, unchanged.

*Enforced in:* `internal/web/assets/style.css`,
`internal/web/assets/index.html`
*Guarded by:* `TestTheFooterLinksAreNotHeldToAProseMeasure`,
`TestTheLandingPageDoesNotStackNoticesUnderTheField`,
`TestTheWordmarkDeclaresATargetFloor`,
`TestTheScannerPageDoesNotRepeatThePrivacyPage`

### W8 — The project's addresses and a check's addresses are different addresses

This project has one check and expects more. A site with one service and a
service with one site are the same thing right up until the second service —
and by then every report anybody has shared points at `/`, so the front page
cannot become a front page without moving the tool out from under those links.

The check was therefore given an address of its own while moving it costs
nothing:

| | |
|---|---|
| `/tls` | the check |
| `/tls/method` | what *this* check cannot establish |
| `POST /api/v1/tls/scan` | the check's API |
| `/web` | the web check |
| `/web/method` | what the web check sends, and cannot establish |
| `POST /api/v1/web/scan` | the web check's API |
| `/privacy`, `/terms` | the project's promises |
| `/.well-known/security.txt`, `/pgp-key.txt` | how a person is reached |
| `GET /api/v1/stats` | the project's counter |

There are two checks now, so the rule that was written ahead of time is being
used: the test holds a list of check prefixes rather than one, and a third
check added without an entry fails rather than quietly putting a page at the
root. The method page arrived before the page a visitor scans from, because
the web probe's user agent had been naming that address in other people's
access logs since the endpoint landed (N7).

**A page says which check it is, and the script believes the page.** One
script serves both, because the builders, the verdict handling, the findings,
the notes, the download and the failure path are the same work — two copies of
all of it would be the drift this file is mostly about. What differs is a
table: the endpoint, the method page, the waiting message and the renderer.
The page declares its row in a data attribute rather than the script inferring
it from the path, because a path is a thing that moves and this project has
moved two already; a script reading the URL would be wrong the day one moves
again, quietly, by drawing a web report with the transport check's renderer.

**And the footer goes to the check the reader is on.** The footer is the one
piece of markup every page shares, so it carried a single method address while
there was a single check — and the day `/web` served a report, "How a report
is read" underneath it pointed at the limits of a TLS handshake. That is the
confusion these pages are separate to prevent, arriving through the only
element that is on every page at once. Each page names its own; a page that is
not a check's takes a default, because a reader who arrived from a report has
to be able to get back to what it means.

Privacy and terms are promises about everything this project runs, not about
one scan, and a copy under each check would be several copies of a promise to
keep in step. The standing limits are the opposite: what a TLS scan cannot
establish is not what a mail check will not establish, and a page trying to be
both would be true of neither.

**The two redirects are deliberately different kinds.** `/method` → `/tls/method`
is **301**: it is not coming back to the root, and the address is printed in
reports that have already been shared. `/` → `/tls` is **302**, because `/` is
going to stop redirecting the day there is a front page to put there. A
permanent redirect is a promise that an address has finished changing, and that
one has not. Nothing may appear in both tables: an address has either finished
moving or it has not. (Every response carries `Cache-Control: no-store`, so
neither is cached in practice; the status code is still the honest one, because
it is read by people and by intermediaries that ignore the header.)

**The API path is aliased, not redirected.** A page can be redirected because a
browser follows a redirect on a `GET` and nothing is lost. A `POST` cannot: 307
and 308 preserve the body, 301 and 302 do not, and clients disagree about which
they follow. A caller whose body is silently dropped receives an error that
looks like it came from the scan rather than from the move. So
`/api/v1/scan` is served by the same handler as `/api/v1/tls/scan` and answers
identically, and both refuse a `GET` — a target in a URL is a target in a
browser history, in a `Referer` header, and in every proxy log on the path.

Every internal link on every page is followed against the routing tables, so a
page that moves cannot leave a dead `href` behind — and the footer is on every
page, which means one stale link is stale everywhere at once.

**And the heading a link aims at exists on the page it aims at.** Stripping
the fragment and stopping there was enough while every link pointed at a page
somebody had just written. It stopped being enough the first time a page was
written against another page's headings: a link to `/privacy#exclusion`
resolved, because `/privacy` resolves, and would have dropped a reader at the
top of a long page with no sign of which part answered them. The section it
meant has never existed under that name.

*Enforced in:* `internal/web.pages`, `internal/web.moved`,
`internal/web.standingIn`, `internal/httpapi.New`
*Guarded by:* `TestTheProjectsPagesStayAtTheRootAndTheChecksDoNot`,
`TestTheRootStandsInAndSaysSoInTheStatusCode`,
`TestEveryInternalLinkResolves`, `TestEachCheckCallsItsOwnPaths`,
`TestEachScanPageDeclaresItsCheck`,
`TestEachCheckPageSendsAReaderToItsOwnLimits`,
`TestEveryAddressThisProjectSendsOutResolves`,
`TestBothScanPathsAreServedAndNeitherRedirects`,
`TestNeitherScanPathAnswersAGet`, `TestOldPathsRedirect`

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

### R9a2 — What an issuer says it checked is reported and not graded

A certificate names the policy it was issued under, and the CA/Browser Forum
reserves four identifiers for the levels every public authority issues at:
domain, individual, organisation and extended validation. They differ in what
was verified about the applicant and in nothing else — the key, the algorithms
and the transport are identical at every level.

It is shown because it is the one thing about a certificate a reader cannot
infer from anything else on the page, and because browsers stopped drawing the
distinction. A visitor to a bank cannot tell from the address bar whether that
certificate proves only that somebody controlled the name, or whether an
authority checked the company exists. The certificate says so and nothing was
showing it.

It is never graded, for the reason R9 gives about CAA in another form: which
level to buy is the operator's decision, and a cheaper one is not a fault. A
domain-validated certificate protects the connection exactly as well as an
extended-validation one, and grading the difference would be this project
selling certificates.

A certificate naming no identifier this table knows gets no row rather than
the word *unknown*. A private authority issues under its own identifiers,
which say nothing that can be read here, and putting a word where a
measurement is missing is the defect this document exists to prevent. A
certificate naming more than one is described by the strongest, which is the
claim its issuer is standing behind.

*Enforced in:* `internal/certinfo.validationLevel`, shown by
`cmd/denyfirst-scan` and `internal/web/assets/app.js`
*Guarded by:* `TestTheValidationLevelIsNamed`,
`TestACertificateWithNoKnownPolicySaysNothing`,
`TestTheStrongestPolicyIsTheOneNamed`, `TestTheValidationLevelIsNotGraded`,
`TestTheValidationLevelIsOnTheFaceOfTheReport`,
`TestBothFacesOfTheReportShowTheSameFacts`

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

**The name carries the check as well as the number.** A number on its own
stops meaning one thing the moment this project runs a second check:
`denyfirst-v7` over a mail report and `denyfirst-v7` over a TLS report would be
the same name over two different rule sets, which is exactly the confusion the
name is printed to prevent. So `denyfirst-v6` became `denyfirst-tls-v6` while
there was one rule set to rename — **renamed, not renumbered**: no rule moved
with the name, the change log says so, and the two names are comparable.

The older names in the record stay as they were. Reports carrying
`denyfirst-v4` exist, and the page is a record of what shipped rather than of
what it would be called today. The test that reads the page therefore accepts
both shapes and keys its sections by the whole name, because a rename
introduces a new name for a number that already had one.

*Enforced in:* `internal/policy.Version`, `docs/policy-changes.md`,
`docs/releasing.md`
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

### S16 — What somebody runs is what they verified

The tool is now the thing people run, and denyfirst.dev is a demonstration of
it (N6). That moves the weight of every supply-chain property in this file: a
compromised release used to reach one server we operate, and now it reaches
whoever ran it.

**The image has no base system and builds nothing.** `FROM scratch`, one
stage, no `RUN`. A container built on alpine or debian carries several hundred
packages this project does not audit and cannot reproduce, which would put a
supply chain underneath a program that deliberately has none — `go.mod` has no
`require` block. And a builder stage would produce bytes nobody has checked:
the argument here is that the release is signed and reproduced by a machine
the maintainer does not control, so the image is a wrapper around **the binary
from that release**, verified before it goes in. A second distribution channel
with weaker guarantees than the first would become the real security level.

**The trust store comes from the machine running it, not from the image.** Not
a convenience. Every verdict about a chain is a verdict against some trust
store, and a report should reflect the reader's rather than one baked in by
whoever built an image. The standing limits already say a scan consults one
trust store; the compose file is where somebody chooses which, mounted
read-only.

**An empty trust store stops the service starting.** This is the failure that
does not look like one: a machine with no store does not fail to verify
chains, it verifies them all as untrusted, and every report then says the
scanned server's certificate does not reach a trusted root — a finding about
the container, printed as a finding about somebody else's server. A container
built `FROM scratch` with nothing mounted is the ordinary way to arrive there.

The check takes the pool rather than fetching it, because the standard library
builds the system pool once per process: a test that arranged an empty store
would get whatever the first caller in the test binary had cached and would
pass or fail on test order. The decision is the testable part, so the decision
is what is separable — and a second assertion reads the source to confirm
something still calls it before anything is served, because removing the call
left every assertion about the decision green.

**The self-hosting page points at the verification procedure rather than
restating it.** Two copies drift, and the copy nobody is reading is the one
that goes wrong — the same rule `docs/releasing.md` follows about the build
command.

*Enforced in:* `Dockerfile`, `docker-compose.yml`, `docs/self-host.md`,
`cmd/denyfirstd.trustStoreUsable`
*Guarded by:* `TestTheImageHasNoBaseSystem`,
`TestTheComposeFileTakesAwayWhatItSays`,
`TestAnEmptyTrustStoreStopsTheServiceStarting`,
`TestSelfHostPointsAtTheVerificationProcedureRatherThanRestatingIt`,
`TestTheSelfHostingPageIsReachableAndItsLinksResolve`

---

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
  both now have a test. It happened a third time with the counters: the page
  said one number per scan plus strong, weak and insecure, and ended *that is
  the whole record*, while `/api/v1/stats` had grown `ungraded`, a block per
  check naming its own rule set, a count of refusals by reason, and three
  figures about dates. Nothing in any of that describes a person, so it was not
  a privacy failure — it was the page being unusable for the one thing it is
  for, which is checking. Its lede was loose in the same way, offering *not the
  result* while verdicts were being counted.

  That one is now mechanical rather than remembered: the figures are read off
  the published type by reflection and each must be described on the page, so a
  counter cannot be added without this failing. What remains is the general
  case. These pages make claims in prose, a test can only check the sentences
  somebody thought to pin, and every rule added to `internal/policy` is a
  chance for one of them to go quietly wrong. Re-read them whenever a policy
  version changes, and where a claim can be pinned to a type rather than to a
  phrase, pin it to the type.