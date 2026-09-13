package httpapi

import (
	"testing"

	"github.com/denyfirst/denyfirst/internal/dnsclient"
	"github.com/denyfirst/denyfirst/internal/scan"
)

// A resolver the operator named reaches the mail check, which makes more
// lookups than any other. Without the copy the transport check would ask the
// named resolver and the mail check the machine's own — two answers about one
// domain from two places, in one report.
func TestAServiceResolverReachesTheMailCheck(t *testing.T) {
	named := &dnsclient.Client{Server: "192.0.2.53:53"}
	s := New(&scan.Scanner{Resolver: named}, Limits{}, nil)

	if got, ok := s.mail.Resolver.(*dnsclient.Client); !ok || got != named {
		t.Errorf("the mail check asks %+v; the service was given %+v", s.mail.Resolver, named)
	}
}
