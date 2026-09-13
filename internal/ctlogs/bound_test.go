package ctlogs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// listNaming writes an unsigned list naming n logs, each with a real key and the
// identifier RFC 6962 derives from it, so that nothing but the count can refuse
// it.
func listNaming(t *testing.T, keys [][]byte, n int) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"version":"1","log_list_timestamp":"2026-01-01T00:00:00Z","operators":[{"name":"x","logs":[`)
	for i := 0; i < n; i++ {
		id := sha256.Sum256(keys[i])
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"description":"log %d","log_id":"%s","key":"%s","state":{"usable":{}}}`,
			i, base64.StdEncoding.EncodeToString(id[:]), base64.StdEncoding.EncodeToString(keys[i]))
	}
	b.WriteString(`]}]}`)
	return []byte(b.String())
}

// A list naming more logs than a list should is refused rather than held.
//
// The list is Google's and signed, so this bound is not reachable by a stranger
// today. It is here for the day the list comes from somewhere with less at
// stake, and a sabotage removing it escaped every test on 2026-09-14 — so the
// bound is now measured from both sides: exactly maxLogs is read, one more is
// refused, and nothing else about the two lists differs.
func TestAListNamingTooManyLogsIsRefused(t *testing.T) {
	keys := make([][]byte, maxLogs+1)
	for i := range keys {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		if keys[i], err = x509.MarshalPKIXPublicKey(&key.PublicKey); err != nil {
			t.Fatalf("marshalling: %v", err)
		}
	}

	if list, err := read(listNaming(t, keys, maxLogs)); err != nil || list.Len() != maxLogs {
		t.Fatalf("a list naming exactly %d logs gave %v; the bound is refusing more than it should", maxLogs, err)
	}
	if _, err := read(listNaming(t, keys, maxLogs+1)); err == nil {
		t.Errorf("a list naming %d logs was held; the bound is %d", maxLogs+1, maxLogs)
	}
}
