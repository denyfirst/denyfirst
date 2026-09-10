package scan

import (
	"context"
	"strings"
	"testing"
)

// The check has to sit where the connection is made, not only where a request
// arrives. A guard in one caller disappears the moment a second is written.
//
// The list itself moved to internal/exclusion on 2026-09-10, and this test
// stayed here with the subject rather than with the file: what it asks is
// whether this scanner refuses the name, which is a question about this
// package. Whether the list matches at a label boundary is a question about
// the matcher, and it is asked where the matcher is.
func TestScannerRefusesExcludedNames(t *testing.T) {
	s := &Scanner{}

	for _, target := range []string{"army.mil", "www.cia.gov", "nasa.gov:443"} {
		_, err := s.Scan(context.Background(), target)
		if err == nil {
			t.Errorf("Scan(%s) was not refused", target)
			continue
		}
		if !strings.Contains(err.Error(), "does not scan") {
			t.Errorf("Scan(%s) failed for the wrong reason: %v", target, err)
		}
	}
}
