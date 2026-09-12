package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
)

// The files somebody runs this from, and what they are allowed to say.
//
// A container image and a compose file are configuration, which is the part of
// a system nobody tests and everybody edits. These are the promises they make.

func repoFile(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("../../" + name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(body)
}

// The image has no base system.
//
// A container built on alpine or debian carries several hundred packages this
// project does not audit and cannot reproduce, which would put a supply chain
// underneath a program that deliberately has none: go.mod has no require
// block. An image with a base system is a second distribution channel with
// weaker guarantees than the first, and the weakest channel is the real
// security level.
func TestTheImageHasNoBaseSystem(t *testing.T) {
	dockerfile := repoFile(t, "Dockerfile")

	from := regexp.MustCompile(`(?mi)^FROM\s+(\S+)`).FindAllStringSubmatch(dockerfile, -1)
	if len(from) == 0 {
		t.Fatal("the Dockerfile has no FROM line")
	}
	for _, m := range from {
		if m[1] != "scratch" {
			t.Errorf("the image is built on %q; only scratch carries nothing to audit", m[1])
		}
	}
	if len(from) != 1 {
		t.Errorf("the Dockerfile has %d stages; a builder stage produces bytes nobody verified, "+
			"and the binary is meant to be the one from the signed release", len(from))
	}

	// It must not build. A RUN line in an image with no shell cannot work
	// anyway, and its presence would mean somebody had reached for a base.
	if regexp.MustCompile(`(?mi)^RUN\s`).MatchString(dockerfile) {
		t.Error("the Dockerfile runs a command, which an image with no shell cannot do")
	}

	// And it must say where the binary comes from, because an image built
	// around an unverified download is the whole chain undone.
	if !strings.Contains(dockerfile, "docs/verify.md") {
		t.Error("the Dockerfile does not point at the verification procedure")
	}
}

// The container is given nothing it does not need, and one thing it does.
//
// The trust store is the one that matters. Every verdict about a chain is a
// verdict against some trust store, and an image with none does not fail to
// verify — it verifies everything as untrusted, and prints a finding about the
// container as a finding about the scanned server.
func TestTheComposeFileTakesAwayWhatItSays(t *testing.T) {
	compose := repoFile(t, "docker-compose.yml")

	for _, want := range []string{
		"read_only: true",
		"no-new-privileges:true",
		"cap_drop",
		"- ALL",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("the compose file no longer sets %q", want)
		}
	}

	if !strings.Contains(compose, "/etc/ssl/certs:/etc/ssl/certs:ro") {
		t.Error("the trust store is not mounted read-only from the host, so a report would " +
			"reflect whatever an image was built with, or nothing at all")
	}
	if !strings.Contains(compose, "SSL_CERT_DIR") {
		t.Error("nothing points the process at the mounted trust store")
	}

	// The container binds an unprivileged port and the host publishes 443, so
	// no capability is needed inside. A privileged bind here would be a
	// capability added to a container that drops all of them.
	if !strings.Contains(compose, `"443:8443"`) {
		t.Error("the published port mapping changed; the container is meant to bind above 1024")
	}
	if regexp.MustCompile(`(?m)^\s*privileged:\s*true`).MatchString(compose) {
		t.Error("the compose file asks for a privileged container")
	}
}

// The self-hosting page points at the verification procedure rather than
// repeating it.
//
// Two copies of a verification procedure drift, and the copy nobody is reading
// is the one that goes wrong. docs/releasing.md has the same rule for the same
// reason.
func TestSelfHostPointsAtTheVerificationProcedureRatherThanRestatingIt(t *testing.T) {
	doc := repoFile(t, "docs/self-host.md")

	if !strings.Contains(doc, "verify.md") {
		t.Error("the self-hosting page does not point at docs/verify.md")
	}
	if strings.Contains(doc, "ssh-keygen -Y verify") {
		t.Error("the self-hosting page restates the signature check, which is a second copy to keep in step")
	}

	// It has to say the thing that is only true here: the trust store is the
	// reader's, and an empty one is a wrong answer rather than a failure.
	for _, want := range []string{
		"trust store",
		"refuses to start",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the self-hosting page does not say %q", want)
		}
	}
}

// Everything that points somewhere points at something that exists.
func TestTheSelfHostingPageIsReachableAndItsLinksResolve(t *testing.T) {
	if !strings.Contains(repoFile(t, "README.md"), "docs/self-host.md") {
		t.Error("the README does not point at the self-hosting page")
	}

	doc := repoFile(t, "docs/self-host.md")
	for _, m := range regexp.MustCompile(`\]\(([a-z0-9./-]+\.md)[^)]*\)`).FindAllStringSubmatch(doc, -1) {
		if _, err := os.Stat("../../docs/" + m[1]); err != nil {
			t.Errorf("docs/self-host.md links %s, which is not there", m[1])
		}
	}
}

// An empty trust store is refused before anything is served.
//
// It is the failure that does not look like one. A machine with no trust store
// — a container built FROM scratch with nothing mounted is the ordinary way to
// get one — does not fail to verify chains. It verifies them all as untrusted,
// and every report says the scanned server's certificate does not reach a
// trusted root: a finding about this machine, printed as a finding about
// somebody else's server, which is the exact mistake this project exists to
// avoid.
func TestAnEmptyTrustStoreStopsTheServiceStarting(t *testing.T) {
	if err := trustStoreUsable(x509.NewCertPool(), nil); err == nil {
		t.Error("an empty trust store was accepted; every report would call every certificate untrusted")
	}
	if err := trustStoreUsable(nil, nil); err == nil {
		t.Error("a nil trust store was accepted")
	}
	if err := trustStoreUsable(nil, errors.New("no")); err == nil {
		t.Error("an unreadable trust store was accepted")
	}

	// The message has to say what to do. "Trust store empty" sends a reader
	// looking for a bug in this program.
	err := trustStoreUsable(x509.NewCertPool(), nil)
	for _, want := range []string{"untrusted", "SSL_CERT_DIR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// And a real one is accepted, or this test would pass with the check
	// wired backwards.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(selfSignedPEM(t)) {
		t.Fatal("the test certificate did not parse")
	}
	if err := trustStoreUsable(pool, nil); err != nil {
		t.Errorf("a populated trust store was refused: %v", err)
	}

	// And something calls it, before anything is served.
	//
	// A guard nothing reaches is a guard that passes its own tests and stops
	// nothing: removing the call from run() left every assertion above green.
	// Read from the source because run() parses flags and binds a port, and a
	// test that did both would be testing the harness.
	source := repoFile(t, "cmd/porchd/main.go")

	call := strings.Index(source, "trustStoreUsable(")
	if call < 0 {
		t.Fatal("nothing checks the trust store before the service starts")
	}
	serve := strings.Index(source, "ListenAndServe")
	if serve >= 0 && call > serve {
		t.Error("the trust store is checked after the service is already answering")
	}

	// And the store that was checked is the store that decides.
	//
	// This half was missing, and its absence was the defect. The check read a
	// pool, satisfied itself that it was not empty, and dropped it; the
	// scanner was then built with no Roots at all. x509.Verify reads a nil
	// Roots as "decide for yourself", and on Windows and macOS deciding means
	// the platform verifier — a different store, which this check never
	// looked at. So the guard passed against one thing and every chain was
	// judged against another, on the two platforms self-hosting is most
	// likely to run on.
	//
	// Asserted on the source for the same reason the call above is: run()
	// parses flags and binds a port, and a test that did both would be
	// testing the harness. Matched on the pool reaching the scanner rather
	// than on any particular spelling of the call, so that improving the
	// prose around it does not fail this.
	if !strings.Contains(source, "scan.Scanner{Roots:") {
		t.Error("the scanner is built without a trust store, so the pool checked above decides " +
			"nothing and every chain is judged against whatever the platform picks")
	}
}

// selfSignedPEM is one certificate, so a pool can be non-empty.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trust store test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A binary says which hosts it will connect to.
//
// The two builds are indistinguishable from outside until one of them refuses
// something. A deploy that installed the wrong one would look entirely
// correct — the file is in place, the service answers, the version matches —
// and the only symptom would be a public scanner nobody meant to run. So the
// binary says, and the deploy procedure reads what it says rather than
// trusting a filename.
func TestAVersionSaysWhichHostsTheBinaryWillReach(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		line := reach(scoped)

		if strings.TrimSpace(line) == "" {
			t.Fatal("a binary says nothing about which hosts it will reach")
		}
		if strings.HasSuffix(line, ".") {
			t.Error("the line ends in a full stop; the deploy procedure matches on its start and shape")
		}

		if demo.Enabled {
			if !strings.HasPrefix(line, "demonstration: ") {
				t.Errorf("a demonstration build says %q, which the deploy check does not match", line)
			}
			// Read from the list the scanner enforces, so a binary cannot say
			// one thing and do another.
			for _, host := range demo.Targets() {
				if !strings.Contains(line, host) {
					t.Errorf("the binary reaches %s and does not say so: %q", host, line)
				}
			}
			continue
		}

		if strings.HasPrefix(line, "demonstration") {
			t.Errorf("the ordinary build calls itself a demonstration: %q", line)
		}
	}
}

// The line says which of the two boundaries this deployment has.
//
// It named only the compiled-in list, so a service requiring proof of control
// said it "scans whatever it is pointed at" — the sentence an operator reads as
// a reason to go and check their configuration. Wrong in the alarming direction
// is still a line nobody trusts the second time, and the deploy procedure reads
// this line rather than trusting a filename.
func TestTheReachLineSaysWhetherAScopeIsConfigured(t *testing.T) {
	if demo.Enabled {
		// A demonstration build's list is compiled in and a scope cannot widen
		// or narrow it, so the line says the same thing either way. Asserted
		// rather than skipped: a build that started describing a scope it does
		// not enforce would be the same defect in the other direction.
		if reach(false) != reach(true) {
			t.Errorf("a demonstration build describes itself differently with a scope: %q and %q",
				reach(false), reach(true))
		}
		return
	}

	open, bounded := reach(false), reach(true)
	if open == bounded {
		t.Fatalf("a deployment that requires proof of control says the same thing as one that "+
			"does not: %q", open)
	}
	if !strings.Contains(open, "whatever it is pointed at") {
		t.Errorf("an unbounded deployment does not say it is unbounded: %q", open)
	}
	if !strings.Contains(bounded, "shown control of") {
		t.Errorf("a bounded deployment does not say what bounds it: %q", bounded)
	}
	if strings.Contains(bounded, "whatever it is pointed at") {
		t.Errorf("a bounded deployment describes itself as unbounded: %q", bounded)
	}
}

// And -version prints it.
//
// A line nothing prints is a line the deploy check greps for and never finds,
// which fails in the direction of refusing a correct deploy — but it would
// also pass silently if somebody replaced the grep. Read from the source,
// because -version calls os.Exit's neighbour and a test that drove it would
// be testing the harness.
func TestTheVersionOutputCarriesTheReachLine(t *testing.T) {
	source := repoFile(t, "cmd/porchd/main.go")

	block := source[strings.Index(source, "if *showVersion {"):]
	block = block[:strings.Index(block, "return 0")]

	if !strings.Contains(block, "reach(") {
		t.Error("-version does not say which hosts the binary will reach, so the deploy check " +
			"has nothing to read and the two builds stay indistinguishable")
	}
}

// The demonstration build is released, and the deploy installs that one.
//
// A property compiled into a binary is worth nothing until the binary
// carrying it is the binary that runs — and a binary that runs here is one
// that was released: signed, listed in SHA256SUMS, and rebuilt by the
// reproduction workflow like every other artifact.
func TestTheDemonstrationBuildIsReleasedAndDeployed(t *testing.T) {
	build := repoFile(t, "scripts/build.sh")

	if !strings.Contains(build, "-tags demo") {
		t.Fatal("the release does not build the demonstration binary, so there is nothing signed to deploy")
	}
	if !strings.Contains(build, "porchd-demonstration_${tag}_linux_amd64") {
		t.Error("the demonstration artifact is not named as the deploy procedure expects")
	}

	releasing := repoFile(t, "docs/releasing.md")

	if !strings.Contains(releasing, "porchd-demonstration_${V}_linux_amd64") {
		t.Error("the deploy procedure does not install the demonstration binary")
	}
	if strings.Contains(releasing, "~/deploy/porchd_${V}_linux_amd64") {
		t.Error("the deploy procedure still installs the unrestricted binary")
	}

	// And it reads what the binary says rather than trusting the filename.
	if !strings.Contains(releasing, "grep -q '^demonstration: '") {
		t.Error("the deploy procedure does not check which build it just installed")
	}
}

// The self-hosting page says plainly what an unbounded service is.
//
// It described the defaults accurately and left the consequence to be worked
// out: a table row saying "which hosts: whichever you point it at" is true, and
// it reads as a capability rather than as a warning. Somebody binding the
// service to an interface so their team can reach it has then built, inside
// their own network, the arrangement this project dismantled for its own public
// deployment — and it is their address in the scanned party's logs.
//
// On this page rather than only in docs/scope.md, because this is the page
// somebody follows while setting the service up. A warning they meet afterwards
// is a warning about something they have already done.
func TestTheSelfHostingPageSaysWhatAnUnboundedServiceIs(t *testing.T) {
	page := repoFile(t, "docs/self-host.md")

	for _, want := range []string{
		"open scanner",
		"-verification-secret-file",
		"your* address",
	} {
		// The middle phrase is the flag that fixes it; a warning naming no
		// remedy is one a reader cannot act on.
		if want == "your* address" {
			if !strings.Contains(page, "*your* address") {
				t.Error("the page does not say whose address ends up in the scanned party's logs")
			}
			continue
		}
		if !strings.Contains(page, want) {
			t.Errorf("docs/self-host.md does not mention %q", want)
		}
	}

	// And it says which of the two a running service is, because that is what
	// an operator checks rather than what they remember configuring.
	if !strings.Contains(page, "shown control of") {
		t.Error("the page does not show what a bounded deployment's -version line says, so an " +
			"operator has no way to confirm which one they have")
	}
}

// The release procedure does not tell anybody to run a command that cannot work.
//
// `gh pr checks --watch` in the same breath as `gh pr create` reports that no
// checks exist and exits, because none has registered yet. The merge then fails
// with required checks not satisfied, which reads like a branch-protection
// problem — and branch protection is working correctly, so the next half hour
// goes on the wrong thing.
func TestTheReleaseProcedureSaysToWaitForChecksToRegister(t *testing.T) {
	page := repoFile(t, "docs/releasing.md")

	if !strings.Contains(page, "gh pr checks --watch") {
		t.Fatal("the procedure no longer watches the checks at all")
	}
	if !strings.Contains(page, "no checks exist") {
		t.Error("the procedure does not warn that watching too early reports nothing and exits, " +
			"which is the failure that reads like a policy block")
	}
}

// The self-hosting page says how to keep results, and what that does not mean.
//
// The sentence it replaces was a promise: "nothing about a scan is written to
// disk". That is still the default and it is no longer the whole story, so the
// page has to carry both halves — and the half a reader most needs is the one
// about what keeping results does *not* turn on.
func TestTheSelfHostingPageExplainsKeepingResults(t *testing.T) {
	page := repoFile(t, "docs/self-host.md")

	for _, want := range []string{
		"-results-dir",
		"-results-keep",
		"porch-scan -history",

		// The three things that make it safe to offer at all.
		"never served over HTTP",
		"65534:65534",
		"read_only: true",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/self-host.md does not mention %q", want)
		}
	}

	// The ownership step is the one that fails silently and confusingly: the
	// image is scratch, so there is no shell in the container to fix it with.
	if !strings.Contains(page, "chown 65534:65534") {
		t.Error("the page does not say the volume must be owned before it is mounted, which is " +
			"a permission denied with no shell in the image to diagnose it")
	}
}
