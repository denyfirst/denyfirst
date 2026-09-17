package smtptls

import "testing"

// A configured name that would not be sent is refused, and only such a name.
//
// heloName falls back to this machine's own name when the configured one is
// unusable, which is right in a scan and wrong at start-up: the operator set a
// name so as not to send the machine's (audit A26).
func TestAnUnusableEHLONameIsRefusedAtStart(t *testing.T) {
	for _, name := range []string{"", "mail.example.test", "scanner", "mail.example.test.", "a-b.example"} {
		if err := CheckHeloName(name); err != nil {
			t.Errorf("%q, which would be sent, was refused: %v", name, err)
		}
	}
	for _, name := range []string{"bad name", "-lead.example", ".lead.example", "x\r\nMAIL FROM:<a@b>",
		"[192.0.2.1]", "naïve.example", string(make([]byte, 300))} {
		if err := CheckHeloName(name); err == nil {
			t.Errorf("%q, which heloName would pass over, was accepted", name)
		}
	}
}
