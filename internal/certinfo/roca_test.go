package certinfo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// Two moduli built the way RSALib built them.
//
// Not borrowed from a corpus and not a vector copied out of a paper: each is
// the product of two primes of the form k·M + (65537^a mod M), constructed by
// the test below and frozen here so that the detector is exercised on every
// run without spending the time to search for primes again.
//
// The first is the 512-bit case, where M is the product of the first 39
// primes, and it is 511 bits — one short of the key size, which is why the
// size guard sits well below 512. The second is the 1024-bit case, with the
// first 71 primes.
var rocaModuli = []string{
	"4ead20557f48391412acd73828898767071b9c6e690b75d19b45d86b13a37c1d" +
		"a36a8beb50a9eac938a694d43246715ad37ef8e6f31be1eba2c1889fcc682101",
	"6f5c69b894551a8d5e4e709b857b6d1eab35c8cec87fad6b6bda42b902543846" +
		"8fbdd4b03387258c43d54d4a49bb879674c9806882faa8111a436f455cd48bca" +
		"546ffd16a22152ba9298d6bca7fe02f1efa81a0dbbc84bc69fdfd9b4f9551b67" +
		"3656eb44c011880e9fdc1907e3be527b5f5200bebe5cae84ad13c65602309b6b",
}

func TestAKeyFromTheBrokenGeneratorIsRecognised(t *testing.T) {
	for _, hex := range rocaModuli {
		n, ok := new(big.Int).SetString(hex, 16)
		if !ok {
			t.Fatalf("the frozen modulus is not a number: %s", hex)
		}
		if !rocaFingerprint(n) {
			t.Errorf("a modulus built the way RSALib built them was not recognised (%d bits)", n.BitLen())
		}
	}
}

// The direction that matters more. A false accusation here says a server's key
// can be factored, which is the most serious thing this report can say about
// anything, and it would be said about a key that is perfectly sound.
func TestAnOrdinaryKeyIsNotAccused(t *testing.T) {
	for i := 0; i < 8; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating a key: %v", err)
		}
		if rocaFingerprint(key.N) {
			t.Fatalf("an ordinary 2048-bit key was accused of the fingerprint:\n%x", key.N)
		}
	}
}

// Nothing small is judged at all.
//
// 1 is in every subgroup, so a modulus of 1 passes every residue test. So does
// 65537 itself, and every power of it small enough to be written down. None of
// these is a key, and the point of the guard is that none of them is accused
// of being a broken one.
func TestNothingTooSmallToBeAKeyIsJudged(t *testing.T) {
	for _, n := range []*big.Int{
		nil,
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(-1),
		big.NewInt(65537),
		new(big.Int).Exp(big.NewInt(65537), big.NewInt(5), nil),
	} {
		if rocaFingerprint(n) {
			t.Errorf("%v was judged, and it is not a key", n)
		}
	}
}

// The frozen moduli above are only worth what the construction that made them
// is worth, so the construction runs too.
//
// A prime of the form k·M + (65537^a mod M), twice, multiplied: that is what
// the library did, and if the detector stopped recognising it this would say
// so even if somebody had edited the frozen values into agreement.
func TestTheDetectorRecognisesAKeyBuiltNow(t *testing.T) {
	if testing.Short() {
		t.Skip("searching for primes")
	}

	p := rsalibPrime(t, 256, 39)
	q := rsalibPrime(t, 256, 39)
	n := new(big.Int).Mul(p, q)

	if !rocaFingerprint(n) {
		t.Fatalf("a modulus built now the way RSALib built them was not recognised:\n%x", n)
	}
}

// rsalibPrime builds one prime the way the broken library did.
func rsalibPrime(t *testing.T, bits, primorial int) *big.Int {
	t.Helper()

	primes := []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
		173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
		271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353}
	if primorial > len(primes) {
		t.Fatalf("this test carries only %d primes", len(primes))
	}

	m := big.NewInt(1)
	for _, p := range primes[:primorial] {
		m.Mul(m, big.NewInt(p))
	}
	room := bits - m.BitLen()
	if room < 1 {
		t.Fatalf("M is %d bits, which leaves no room for a %d-bit prime", m.BitLen(), bits)
	}

	e := big.NewInt(65537)
	ceiling := new(big.Int).Lsh(big.NewInt(1), uint(room))
	for attempt := 0; attempt < 200; attempt++ {
		a, err := rand.Int(rand.Reader, big.NewInt(1<<20))
		if err != nil {
			t.Fatalf("choosing an exponent: %v", err)
		}
		c := new(big.Int).Exp(e, a, m)

		for i := 0; i < 20000; i++ {
			k, err := rand.Int(rand.Reader, ceiling)
			if err != nil {
				t.Fatalf("choosing a multiplier: %v", err)
			}
			candidate := new(big.Int).Add(new(big.Int).Mul(k, m), c)
			if candidate.BitLen() == bits && candidate.ProbablyPrime(20) {
				return candidate
			}
		}
	}
	t.Fatal("no prime of the RSALib form was found, which should not happen")
	return nil
}

// The whole path, because a fingerprint nothing carries into the report is a
// fingerprint nobody sees.
//
// A working private key is built from two RSALib primes — the same
// construction, kept whole rather than thrown away after the modulus — and it
// signs a certificate. What is being checked is not the mathematics again but
// the wiring: that Analyse reads the key, that the fact reaches the rule, and
// that the rule says the thing about the key rather than about the chain.
func TestTheFingerprintReachesTheReport(t *testing.T) {
	if testing.Short() {
		t.Skip("searching for primes")
	}

	key := rsalibKey(t)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "roca.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"roca.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing it back: %v", err)
	}

	report, err := Analyse([]*x509.Certificate{leaf}, "roca.test", time.Now())
	if err != nil {
		t.Fatalf("analysing: %v", err)
	}

	var found *policy.Finding
	for i, f := range report.Grade.Findings {
		if f.RuleID == "cert.roca" {
			found = &report.Grade.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("the certificate carries the fingerprint and no finding says so; findings were %v",
			report.Grade.Findings)
	}
	if found.Verdict != policy.Insecure {
		t.Errorf("a factorable key is graded %s", found.Verdict)
	}

	// The claim has to be about how the key was made. "We factored this" is a
	// different statement and it is not the one that was established.
	if strings.Contains(strings.ToLower(found.Rationale), "we factored") {
		t.Error("the rationale claims a factorisation this service did not perform")
	}
	if !strings.Contains(found.Rationale, "fingerprint") {
		t.Error("the rationale does not say that what was found is a fingerprint")
	}
}

// rsalibKey builds a usable RSA key from two primes of the broken form.
func rsalibKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	for attempt := 0; attempt < 8; attempt++ {
		p := rsalibPrime(t, 512, 71)
		q := rsalibPrime(t, 512, 71)
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
		e := big.NewInt(65537)
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: 65537},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		key.Precompute()
		if err := key.Validate(); err != nil {
			continue
		}
		if !rocaFingerprint(key.N) {
			t.Fatal("a key built from RSALib primes does not carry the fingerprint")
		}
		return key
	}

	t.Fatal("no usable key of the RSALib form was built")
	return nil
}

// The primes are the ones the library's M is built from, with none dropped.
//
// A list of thirty-eight numbers is a list nobody reads. Dropping one leaves a
// test that still recognises every key in the corpus and is quietly weaker
// against a modulus that is not one — which is the sort of change that passes
// every other test in this file, as it did when it was tried.
func TestThePrimesAreTheFirstOddPrimes(t *testing.T) {
	prime := func(n uint64) bool {
		if n < 2 {
			return false
		}
		for d := uint64(2); d*d <= n; d++ {
			if n%d == 0 {
				return false
			}
		}
		return true
	}

	// Every odd prime up to the last one listed, in order, and nothing else.
	var want []uint64
	for n := uint64(3); n <= rocaPrimes[len(rocaPrimes)-1]; n += 2 {
		if prime(n) {
			want = append(want, n)
		}
	}

	if len(want) != len(rocaPrimes) {
		t.Fatalf("there are %d odd primes up to %d and the list holds %d, so one is missing or spare",
			len(want), rocaPrimes[len(rocaPrimes)-1], len(rocaPrimes))
	}
	for i := range want {
		if rocaPrimes[i] != want[i] {
			t.Errorf("position %d holds %d and should hold %d", i, rocaPrimes[i], want[i])
		}
	}
	if len(rocaPrimes) != 38 {
		t.Errorf("the list holds %d primes; the smallest M the library uses is the product of the "+
			"first 39, so 38 odd ones is the floor", len(rocaPrimes))
	}
}
