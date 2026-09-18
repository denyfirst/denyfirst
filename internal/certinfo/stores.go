package certinfo

import (
	"crypto/x509"
	"time"

	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/rootstores"
)

// judgeStores asks the carried root stores of four clients what they make of a
// chain.
//
// At the same moment the trust question above is asked: now, unless the
// certificate is outside its validity window, in which case the middle of it.
// An expired certificate fails every store on its dates, and whether they include
// its root is a separate question with a separate answer (R4b).
func judgeStores(chain []*x509.Certificate, now time.Time) policy.StoreFacts {
	set, err := rootstores.Carried()
	if err != nil {
		return policy.StoreFacts{Reason: "the root stores this build carries did not match their recorded " +
			"fingerprints, so they were not used"}
	}
	if set.Retrieved == "" {
		return policy.StoreFacts{Reason: "this build carries no root stores"}
	}

	if len(chain) > maxChainLength {
		chain = chain[:maxChainLength]
	}
	leaf := chain[0]

	at := now
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		if window := leaf.NotAfter.Sub(leaf.NotBefore); window > 0 {
			at = leaf.NotBefore.Add(window / 2)
		}
	}

	facts := policy.StoreFacts{Retrieved: set.Retrieved}
	for _, j := range set.Judge(chain, at) {
		facts.Stores = append(facts.Stores, policy.StoreTrust{
			Store: j.Store.Name(), Verdict: string(j.Verdict), Root: j.Root, After: j.After,
		})
	}
	return facts
}
