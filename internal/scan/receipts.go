package scan

import (
	"github.com/denyfirst/porch/internal/certinfo"
	"github.com/denyfirst/porch/internal/ctlogs"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// checkReceipts checks every transparency receipt the certificate and the
// handshake carried, and records what that found.
//
// Offline, and on every build including the demonstration: the log list is
// carried rather than fetched, so checking a receipt asks nobody anything.
//
// The issuer comes from the chain the server sent, for the reason revocation
// takes it from there: a log signs a precertificate naming the key of the
// authority that issues it, and that authority is the one in the chain.
func checkReceipts(f *policy.TransparencyFacts, report *tlsprobe.Report) {
	if report == nil || len(report.Certificates) == 0 {
		return
	}

	list, err := ctlogs.Embedded()
	if err != nil {
		// A carried list that does not verify is not Google's list, and a
		// receipt checked against it would be checked against nothing anybody
		// vouched for. Said, and nothing is checked.
		f.ListReason = "the log list this build carries did not verify against Google's key, so it was not used"
		return
	}

	leaf := report.Certificates[0]
	receipts := ctlogs.CheckEmbedded(list, leaf, issuerOf(leaf, report.Certificates))
	receipts = append(receipts, ctlogs.CheckHandshake(list, report.SCTs, leaf)...)

	f.Checked = true
	f.ListVersion = list.Version
	f.ListDate = list.Timestamp.UTC().Format("2006-01-02")

	for _, r := range receipts {
		switch r.Status {
		case ctlogs.Verified:
			f.Verified++
		case ctlogs.BadSignature:
			f.BadSignature++
		case ctlogs.UnknownLog:
			f.UnknownLog++
		default:
			f.Unreadable++
		}
	}
}

// transparencyFor joins what the certificate and the handshake carried, checks
// every receipt, and says whether all of them verified.
//
// A function rather than lines inside Scan, because inside Scan nothing could
// see them: a sabotage deleting the check left every test passing on
// 2026-09-14, since the tests called checkReceipts themselves and a scan that
// never called it looked no different to them.
func transparencyFor(cert *certinfo.Report, report *tlsprobe.Report) (policy.TransparencyFacts, bool) {
	f := policy.TransparencyFacts{
		Embedded:    cert.Transparency.EmbeddedCount,
		InHandshake: report.SCTCount,
		FromLogs:    distinctLogs(cert.Transparency.LogIDs, report.SCTLogIDs),
		Stapled:     report.OCSPStapled,
		Trusted:     cert.Trusted,
	}

	// Whether each receipt is genuine: checked against the log list this
	// build carries, offline.
	checkReceipts(&f, report)
	return f, allReceiptsVerified(f)
}

// allReceiptsVerified is whether every receipt counted was checked and verified.
func allReceiptsVerified(f policy.TransparencyFacts) bool {
	total := f.Embedded + f.InHandshake
	return f.Checked && total > 0 && f.Verified == total
}
