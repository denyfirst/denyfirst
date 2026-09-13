package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// The page reads the field names the API sends for the hand-written hellos.
//
// The seam TestTheConsoleReadsTheFieldNamesTheAPISends guards for the mail
// check, in its TLS form. A name the script reads that the API does not send is
// undefined, which is falsy — so "accepted" misspelled on one side draws
// "not measured" over an SSL 3.0 server that accepted, and nothing errors. That
// is the reassuring failure rather than the loud one.
func TestThePageReadsTheLegacyFieldsTheAPISends(t *testing.T) {
	grade := policy.GradeVersion(policy.VersionSSL30)
	suite := &tlsprobe.CipherResult{CipherFinding: policy.GradeCipher("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA")}

	// Every field set, so nothing is omitted on the way out.
	answer := tlsprobe.LegacyAnswer{
		Measured: true, Accepted: true, Refused: true,
		Version: "SSL 3.0", VersionGrade: &grade, Suite: suite, Reason: "a reason",
	}
	raw, err := json.Marshal(tlsprobe.Legacy{
		Asked: true, SSL3: answer, Export: answer, Null: answer,
		Fallback: tlsprobe.Fallback{Measured: true, Honoured: true, Asked: "TLS 1.2", Reason: "a reason"},
	})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var sent map[string]map[string]any
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	sent = map[string]map[string]any{}
	for key, value := range top {
		if m, ok := value.(map[string]any); ok {
			sent[key] = m
		}
	}

	source := script(t)

	// read reports whether the script reads a property under any of the local
	// names app.js gives the object.
	read := func(field string, names ...string) bool {
		for _, name := range names {
			if strings.Contains(source, name+"."+field) {
				return true
			}
		}
		return false
	}

	for _, key := range []string{"asked", "ssl3", "export", "null", "fallback"} {
		if _, ok := top[key]; !ok {
			t.Errorf("the API sends no legacy.%s", key)
		}
		if !read(key, "l", "legacy") {
			t.Errorf("the page does not read legacy.%s; this test is naming a field nobody uses", key)
		}
	}

	for _, field := range []string{"accepted", "refused", "reason", "version", "versionGrade", "suite"} {
		if _, ok := sent["ssl3"][field]; !ok {
			t.Errorf("the API sends no %s on an answer", field)
		}
	}

	// Checked per place, not "somewhere". The SSL 3.0 row in the version table
	// and the rows in the hand-written section read the same object under two
	// local names, and a test accepting either would pass while one of them
	// misspelled a field the other spelled right.
	for _, field := range []string{"accepted", "refused", "reason", "versionGrade"} {
		if !read(field, "ssl3") {
			t.Errorf("the SSL 3.0 version row does not read ssl3.%s", field)
		}
	}
	for _, field := range []string{"accepted", "refused", "reason", "version", "suite"} {
		if !read(field, "a") {
			t.Errorf("the hand-written section does not read .%s on an answer", field)
		}
	}

	// And the section is drawn at all. Every read above can be present in a
	// function nobody calls.
	if !strings.Contains(source, "legacy(data.tls)") {
		t.Error("the TLS report never calls legacy(), so the hand-written section is never drawn")
	}

	for _, field := range []string{"measured", "honoured", "asked", "reason"} {
		if _, ok := sent["fallback"][field]; !ok {
			t.Errorf("the API sends no fallback.%s", field)
		}
		if !read(field, "f") {
			t.Errorf("the page does not read fallback.%s", field)
		}
	}

	suiteSent, _ := sent["ssl3"]["suite"].(map[string]any)
	for _, field := range []string{"name", "verdict"} {
		if _, ok := suiteSent[field]; !ok {
			t.Errorf("the API sends no suite.%s", field)
		}
		if !read(field, "suite") {
			t.Errorf("the page does not read suite.%s", field)
		}
	}

	gradeSent, _ := sent["ssl3"]["versionGrade"].(map[string]any)
	if _, ok := gradeSent["verdict"]; !ok || !read("verdict", "versionGrade") {
		t.Error("versionGrade.verdict is not sent, or not read, so an accepted SSL 3.0 row draws no grade")
	}
}
