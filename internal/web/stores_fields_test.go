package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/certinfo"
)

// The page reads the stores line under the name the API sends it.
//
// The line is written once, in certinfo, and printed by both faces. A name
// misspelled on this side of the seam leaves the row off the page silently —
// the report would say nothing about the stores at all rather than something
// wrong, which is the quieter failure and the one nobody reports.
func TestThePageReadsTheStoresLineTheAPISends(t *testing.T) {
	raw, err := json.Marshal(certinfo.Report{StoresLine: "trusted by Mozilla (stores of 2026-09-14)"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if _, ok := sent["storesLine"]; !ok {
		t.Error("the API sends no storesLine")
	}
	if !strings.Contains(script(t), "cert.storesLine") {
		t.Error("the page does not read cert.storesLine, so the stores row is never drawn")
	}
}
