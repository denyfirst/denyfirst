package certinfo

import "math/big"

// The ROCA fingerprint, CVE-2017-15361.
//
// Infineon's RSALib built primes of the form
//
//	p = k·M + (65537^a mod M)
//
// where M is the product of the first n primes. Both primes of a key are made
// that way, so the modulus satisfies N ≡ 65537^(a+b) (mod M) — and by the
// Chinese remainder theorem that means N mod p is inside the subgroup 65537
// generates, for every prime p dividing M. Testing those residues is the
// whole detection. It costs a handful of modular reductions.
//
// Nothing here factors anything and nothing here could. The attack that
// follows from this shape is Coppersmith's, it takes weeks to months of
// computation, and this service does not run it and will not. What this
// answers is a different and much cheaper question: was this key made by a
// generator known to produce factorable keys. The report has to say that and
// not more, because "we broke your key" and "your key was made by something
// broken" are different claims and only the second one was established.
//
// The test is a necessary condition rather than a sufficient one. A modulus
// with no relation to RSALib would have to land inside the reachable set
// modulo all thirty-eight primes at once, which is a coincidence somewhere
// around one in 2^100; the published corpora report none. Still, "carries the
// fingerprint" is what is true, and it is what the finding says.

// rocaPrimes are the first thirty-eight odd primes.
//
// Odd, because 2 divides M as well and carries no information: N is odd and
// every power of 65537 is odd, so the test modulo 2 passes for everything.
//
// Thirty-eight is a floor rather than a choice. M is the product of the first
// 39 primes for a 512-bit key and more for larger ones, so these primes divide
// every M the library uses, and a key of any size it generated fails here.
var rocaPrimes = []uint64{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
	157, 163, 167,
}

// rocaMinBits is the smallest modulus this will judge.
//
// The guard is against degenerate values rather than against small keys. 1 is
// in every subgroup, so a modulus of 1 — or any small power of 65537 — passes
// every residue test and would be accused of a fingerprint it does not have.
// Nothing that small is a key; the number here only has to be past it.
//
// It is deliberately well below 512. The library made 512-bit keys, and two
// 256-bit primes multiply to a modulus that is sometimes 511 bits: a threshold
// set at the key size would have missed a genuine RSALib key by one bit, which
// is how a check comes to answer for every case but the one it was written
// for. Measured while writing the test, on a modulus built the way the library
// built them.
const rocaMinBits = 256

// rocaReachable[i] is the set of residues modulo rocaPrimes[i] that powers of
// 65537 can reach.
//
// Computed here rather than written down. Published implementations carry a
// table of precomputed bit masks, which is faster and is a table no reader can
// check: a transposed digit would quietly turn the test into one that answers
// almost the same and not quite. Generating the subgroups takes microseconds
// once, and what it costs in speed it returns in being obviously right.
var rocaReachable = buildROCAReachable()

func buildROCAReachable() []map[uint64]bool {
	out := make([]map[uint64]bool, len(rocaPrimes))
	for i, prime := range rocaPrimes {
		reachable := make(map[uint64]bool, prime)
		for x := uint64(1); !reachable[x]; x = (x * 65537) % prime {
			reachable[x] = true
		}
		out[i] = reachable
	}
	return out
}

// rocaFingerprint reports whether an RSA modulus carries the RSALib shape.
func rocaFingerprint(n *big.Int) bool {
	if n == nil || n.Sign() <= 0 || n.BitLen() < rocaMinBits {
		return false
	}

	remainder := new(big.Int)
	prime := new(big.Int)
	for i, p := range rocaPrimes {
		prime.SetUint64(p)
		if !rocaReachable[i][remainder.Mod(n, prime).Uint64()] {
			return false
		}
	}
	return true
}
