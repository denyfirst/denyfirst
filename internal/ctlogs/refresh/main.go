// Command refresh fetches Chrome's certificate transparency log list, verifies
// Google's signature over it, and writes it where internal/ctlogs carries it.
//
//	go run ./internal/ctlogs/refresh          # fetch, verify, write
//	go run ./internal/ctlogs/refresh -check   # fetch, verify, compare; exit 1 if the logs changed
//
// Not part of any release: it lives under internal/, and scripts/build.sh builds
// porch-scan and porchd and nothing else.
//
// # Why a person commits the result
//
// The obvious arrangement is a scheduled job that runs this and opens a pull
// request. It does not work here, and not by accident: every commit on a pull
// request has to be signed by a key in .github/commit-signers (S6), and giving a
// workflow such a key is handing a machine this project does not control the
// ability to write code that passes as the maintainer's. So the scheduled job
// runs -check, and opens an issue when the logs have changed; a person runs this
// without -check, reads the diff, and commits it signed.
//
// -check compares the logs — identifier and state — and not the file. The
// published list is regenerated often with a new version and timestamp and no
// change to any log, and an issue every day saying nothing had changed would be
// an issue nobody reads.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/denyfirst/porch/internal/ctlogs"
)

const (
	// maxDownload bounds what the publisher can make this hold. The list is
	// tens of kilobytes.
	maxDownload = 4 << 20

	fetchTimeout = 60 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		check = flag.Bool("check", false, "compare the published logs with the carried ones instead of writing")
		dir   = flag.String("dir", "internal/ctlogs", "where the carried list lives")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	list, err := fetch(ctx, ctlogs.ListSource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetching the list: %v\n", err)
		return 2
	}
	signature, err := fetch(ctx, ctlogs.SignatureSource)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetching the signature: %v\n", err)
		return 2
	}

	published, err := ctlogs.Parse(list, signature)
	if err != nil {
		// The one failure that must never be written: a list whose signature
		// does not verify is not Google's list, whatever served it.
		fmt.Fprintf(os.Stderr, "the published list does not verify: %v\n", err)
		return 2
	}

	carried, err := ctlogs.Embedded()
	if err != nil {
		fmt.Fprintf(os.Stderr, "the carried list does not verify: %v\n", err)
		return 2
	}

	added, removed := ctlogs.Difference(carried, published)

	if *check {
		code, lines := checkOutcome(carried.Version, published.Version, added, removed)
		for _, line := range lines {
			fmt.Println(line)
		}
		return code
	}

	if err := os.WriteFile(filepath.Join(*dir, "log_list.json"), list, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "writing the list: %v\n", err)
		return 2
	}
	if err := os.WriteFile(filepath.Join(*dir, "log_list.sig"), signature, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "writing the signature: %v\n", err)
		return 2
	}
	fmt.Printf("wrote version %s (%d logs); %d added or changed, %d removed or changed\n",
		published.Version, published.Len(), len(added), len(removed))
	return 0
}

// checkOutcome decides what -check reports and exits with: 0 when the logs are
// the same, 1 when they differ. The workflow opens an issue on 1 and fails on
// anything else, so this is the number the whole weekly job turns on.
//
// A function so a test can hold it to that. Inside run it could not be seen, and
// a sabotage reporting "no change" for a changed list escaped on 2026-09-14 —
// which would have meant a list going stale with nobody ever told.
func checkOutcome(carriedVersion, publishedVersion string, added, removed []string) (int, []string) {
	if len(added) == 0 && len(removed) == 0 {
		return 0, []string{fmt.Sprintf("the carried logs match the published list (version %s)", publishedVersion)}
	}
	lines := []string{fmt.Sprintf("the published list (version %s) differs from the carried one (version %s)",
		publishedVersion, carriedVersion)}
	for _, line := range added {
		lines = append(lines, "  + "+line)
	}
	for _, line := range removed {
		lines = append(lines, "  - "+line)
	}
	return 1, lines
}

var errTooLarge = errors.New("the response is larger than a log list should be")

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDownload {
		return nil, errTooLarge
	}
	return body, nil
}
