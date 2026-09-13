// Command refresh fetches the root stores of Mozilla, Chrome, Microsoft and
// Apple, checks them against the fingerprints their publishers list, and writes
// the carried file internal/rootstores reads.
//
//	go run ./internal/rootstores/refresh          # fetch, check, write
//	go run ./internal/rootstores/refresh -check   # fetch, check, compare; exit 1 if the stores changed
//
// Not part of any release: it lives under internal/, and scripts/build.sh builds
// porch-scan and porchd and nothing else.
//
// # What is checked, and what cannot be
//
// None of these sources is signed by its publisher. So every certificate taken
// from them has to hash to the SHA-256 fingerprint the same publisher lists
// beside it; every Apple root, which CCADB lists by fingerprint alone, has to be
// found among the certificates the other three publish; and every certificate has
// to parse. A source failing any of that is refused whole, and nothing is
// written. What is left undefended by this — a source served falsely over HTTPS,
// consistent with itself — is what a person reading the diff before signing it is
// for (S6).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/denyfirst/denyfirst/internal/rootstores"
)

const (
	mozillaSource   = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"
	microsoftSource = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSVPEM"
	chromeCerts     = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT"
	chromeProto     = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT"
	appleSource     = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4"

	maxDownload  = 64 << 20
	fetchTimeout = 5 * time.Minute
)

var (
	errSource = errors.New("a source does not agree with itself")

	// errUnparseable is a certificate that matches the fingerprint its publisher
	// lists and that Go cannot parse. Not a source disagreeing with itself: a
	// root Go's verifier could never use, left out and named rather than
	// refusing the whole store it came in. EC-ACC, whose serial number is
	// negative, was the first, on 2026-09-14.
	errUnparseable = errors.New("a certificate matches its fingerprint and cannot be parsed")
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		check = flag.Bool("check", false, "compare the published stores with the carried ones instead of writing")
		dir   = flag.String("dir", "internal/rootstores", "where the carried file lives")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	sources := map[string][]byte{}
	for name, url := range map[string]string{
		"mozilla": mozillaSource, "microsoft": microsoftSource,
		"chrome-certs": chromeCerts, "chrome-proto": chromeProto, "apple": appleSource,
	} {
		body, err := fetch(ctx, url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetching %s: %v\n", name, err)
			return 2
		}
		sources[name] = body
	}

	published, skipped, err := build(sources, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "the published stores were refused: %v\n", err)
		return 2
	}
	for _, name := range skipped {
		fmt.Fprintf(os.Stderr, "not carried, because Go cannot parse it: %s\n", name)
	}

	path := filepath.Join(*dir, "roots.json")
	if *check {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading the carried file: %v\n", err)
			return 2
		}
		var current rootstores.File
		if err := json.Unmarshal(raw, &current); err != nil {
			fmt.Fprintf(os.Stderr, "reading the carried file: %v\n", err)
			return 2
		}
		code, lines := checkOutcome(current, published)
		for _, line := range lines {
			fmt.Println(line)
		}
		return code
	}

	out, err := json.MarshalIndent(published, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encoding: %v\n", err)
		return 2
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "writing: %v\n", err)
		return 2
	}
	fmt.Printf("wrote %d roots\n", len(published.Roots))
	return 0
}

// build turns the five fetched sources into the carried file.
func build(sources map[string][]byte, now time.Time) (rootstores.File, []string, error) {
	roots := map[string]*rootstores.Root{}
	var skipped []string
	put := func(sum, name string, der []byte, store, status string) {
		r, ok := roots[sum]
		if !ok {
			r = &rootstores.Root{SHA256: sum, Name: name, DER: base64.StdEncoding.EncodeToString(der), Stores: map[string]string{}}
			roots[sum] = r
		}
		r.Stores[store] = status
	}
	known := map[string][]byte{}
	names := map[string]string{}

	// Mozilla: roots with the Websites trust bit, and a TLS distrust date where
	// Mozilla sets one.
	mozilla, err := readCSV(sources["mozilla"])
	if err != nil {
		return rootstores.File{}, nil, fmt.Errorf("mozilla: %w", err)
	}
	for _, row := range mozilla.rows {
		der, sum, err := pemMatching(row, mozilla.col["SHA-256 Fingerprint"])
		if errors.Is(err, errUnparseable) {
			skipped = append(skipped, "mozilla: "+row[mozilla.col["Common Name or Certificate Name"]])
			continue
		}
		if err != nil {
			return rootstores.File{}, nil, fmt.Errorf("mozilla: %w", err)
		}
		name := row[mozilla.col["Common Name or Certificate Name"]]
		known[sum], names[sum] = der, name
		if !strings.Contains(row[mozilla.col["Trust Bits"]], "Websites") {
			continue
		}
		status := "trusted"
		if d := row[mozilla.col["Distrust for TLS After Date"]]; d != "" {
			date, err := time.Parse("2006.01.02", d)
			if err != nil {
				return rootstores.File{}, nil, fmt.Errorf("mozilla: a distrust date %q: %w", d, errSource)
			}
			status = "distrust-after:" + date.Format(time.DateOnly)
		}
		put(sum, name, der, "mozilla", status)
	}

	// Microsoft: roots enabled for server authentication. NotBefore roots are
	// conditional: the date they apply from is not in this report.
	microsoft, err := readCSV(sources["microsoft"])
	if err != nil {
		return rootstores.File{}, nil, fmt.Errorf("microsoft: %w", err)
	}
	for _, row := range microsoft.rows {
		der, sum, err := pemMatching(row, microsoft.col["SHA-256 Fingerprint"])
		if errors.Is(err, errUnparseable) {
			skipped = append(skipped, "microsoft: "+row[microsoft.col["CA Common Name or Certificate Name"]])
			continue
		}
		if err != nil {
			return rootstores.File{}, nil, fmt.Errorf("microsoft: %w", err)
		}
		name := row[microsoft.col["CA Common Name or Certificate Name"]]
		known[sum], names[sum] = der, name
		if !strings.Contains(row[microsoft.col["Microsoft EKUs"]], "Server Authentication") {
			continue
		}
		switch row[microsoft.col["Microsoft Status"]] {
		case "Included":
			put(sum, name, der, "microsoft", "trusted")
		case "NotBefore":
			put(sum, name, der, "microsoft", "conditional")
		}
	}

	// Chrome: the trust anchors in root_store.textproto, conditional where the
	// entry carries constraints.
	chromeText, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sources["chrome-proto"])))
	if err != nil {
		return rootstores.File{}, nil, fmt.Errorf("chrome: %w", errSource)
	}
	chromeCertText, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sources["chrome-certs"])))
	if err != nil {
		return rootstores.File{}, nil, fmt.Errorf("chrome: %w", errSource)
	}
	anchors := trustAnchors(chromeText)
	chromeDER := pemsByHash(chromeCertText)
	for sum, constrained := range anchors {
		der, ok := chromeDER[sum]
		if !ok {
			return rootstores.File{}, nil, fmt.Errorf("chrome: anchor %s has no certificate: %w", sum, errSource)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return rootstores.File{}, nil, fmt.Errorf("chrome: %w", errSource)
		}
		known[sum] = der
		if names[sum] == "" {
			names[sum] = cert.Subject.CommonName
		}
		status := "trusted"
		if constrained {
			status = "conditional"
		}
		put(sum, names[sum], der, "chrome", status)
	}

	// Apple: CCADB lists Apple's included roots by fingerprint alone. Each has to
	// be one of the certificates the other three publish; one that is not cannot
	// be carried, and is counted.
	apple, err := readCSV(sources["apple"])
	if err != nil {
		return rootstores.File{}, nil, fmt.Errorf("apple: %w", err)
	}
	for _, row := range apple.rows {
		if row[apple.col["Apple Status"]] != "Included" {
			continue
		}
		sum := strings.ToLower(row[apple.col["SHA-256 Fingerprint"]])
		der, ok := known[sum]
		if !ok {
			// Verified Mark roots, used for mail logos and never for TLS, are
			// the ones this has been on 2026-09-14. Skipped rather than
			// refused: a root with no published certificate cannot be carried.
			continue
		}
		put(sum, names[sum], der, "apple", "trusted")
	}

	file := rootstores.File{
		Retrieved: now.Format(time.DateOnly),
		Sources: map[string]string{
			"mozilla": mozillaSource, "microsoft": microsoftSource,
			"chrome": chromeProto, "apple": appleSource,
		},
	}
	for _, r := range roots {
		file.Roots = append(file.Roots, *r)
	}
	sort.Slice(file.Roots, func(i, j int) bool { return file.Roots[i].SHA256 < file.Roots[j].SHA256 })

	// The same check the package makes on every build, before anything is
	// written.
	raw, err := json.Marshal(file)
	if err != nil {
		return rootstores.File{}, nil, err
	}
	if _, err := rootstores.Parse(raw); err != nil {
		return rootstores.File{}, nil, err
	}
	return file, skipped, nil
}

type table struct {
	col  map[string]int
	rows [][]string
}

func readCSV(raw []byte) (table, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	all, err := r.ReadAll()
	if err != nil || len(all) < 2 {
		return table{}, errSource
	}
	t := table{col: map[string]int{}, rows: all[1:]}
	for i, h := range all[0] {
		t.col[h] = i
	}
	return t, nil
}

// pemMatching finds the certificate in a row and requires it to hash to the
// fingerprint the same row lists.
func pemMatching(row []string, fingerprintCol int) ([]byte, string, error) {
	if fingerprintCol >= len(row) {
		return nil, "", errSource
	}
	want := strings.ToLower(row[fingerprintCol])
	for _, field := range row {
		if !strings.Contains(field, "BEGIN CERTIFICATE") {
			continue
		}
		block, _ := pem.Decode([]byte(strings.Trim(field, "'\" ")))
		if block == nil {
			return nil, "", errSource
		}
		sum := sha256.Sum256(block.Bytes)
		got := hex.EncodeToString(sum[:])
		if got != want {
			return nil, "", fmt.Errorf("certificate %s is listed as %s: %w", got, want, errSource)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, got, errUnparseable
		}
		return block.Bytes, got, nil
	}
	return nil, "", errSource
}

// trustAnchors reads the trust_anchors blocks of root_store.textproto: each
// anchor's hash, and whether it carries constraints.
func trustAnchors(text []byte) map[string]bool {
	out := map[string]bool{}
	var (
		inAnchor    bool
		sum         string
		constrained bool
	)
	scanner := bufio.NewScanner(bytes.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "trust_anchors {"):
			inAnchor, sum, constrained = true, "", false
		case inAnchor && line == "}":
			if sum != "" {
				out[sum] = constrained
			}
			inAnchor = false
		case inAnchor && strings.Contains(line, "sha256_hex:"):
			sum = strings.ToLower(strings.Trim(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), `"`))
		case inAnchor && strings.Contains(line, "constraints:"):
			constrained = true
		}
	}
	return out
}

// pemsByHash decodes every certificate in a PEM file, keyed by its hash.
func pemsByHash(text []byte) map[string][]byte {
	out := map[string][]byte{}
	for {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			return out
		}
		sum := sha256.Sum256(block.Bytes)
		out[hex.EncodeToString(sum[:])] = block.Bytes
	}
}

// checkOutcome decides what -check reports: 0 when the stores say the same thing
// of the same roots, 1 when they do not. Retrieval dates are not compared.
func checkOutcome(current, published rootstores.File) (int, []string) {
	have := map[string]bool{}
	for _, line := range rootstores.Summary(current) {
		have[line] = true
	}
	want := map[string]bool{}
	var added, removed []string
	for _, line := range rootstores.Summary(published) {
		want[line] = true
		if !have[line] {
			added = append(added, line)
		}
	}
	for _, line := range rootstores.Summary(current) {
		if !want[line] {
			removed = append(removed, line)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return 0, []string{fmt.Sprintf("the carried stores match the published ones (%d roots)", len(published.Roots))}
	}
	lines := []string{fmt.Sprintf("the published stores differ from the carried ones (retrieved %s)", current.Retrieved)}
	for _, line := range added {
		lines = append(lines, "  + "+line)
	}
	for _, line := range removed {
		lines = append(lines, "  - "+line)
	}
	return 1, lines
}

var errTooLarge = errors.New("the response is larger than a root store report should be")

// fetch gets one source, trying again when the connection fails.
//
// Again only on a failed connection, never on an answer. CCADB's full records
// report is ten megabytes and its host reset the connection partway through on
// 2026-09-14, on the same URL that had downloaded a minute before; a person
// running this should not have to run it three times. A status other than 200
// is an answer, and trying it again would be arguing with it.
func fetch(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 5 * time.Second):
			}
		}
		body, err, retry := fetchOnce(ctx, url)
		if err == nil || !retry {
			return body, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// fetchOnce makes one request, and says whether its failure is worth another.
func fetchOnce(ctx context.Context, url string) (body []byte, err error, retry bool) {
	body, err = download(ctx, url)
	var status statusError
	return body, err, err != nil && !errors.As(err, &status) && !errors.Is(err, errTooLarge)
}

type statusError int

func (s statusError) Error() string { return fmt.Sprintf("status %d", int(s)) }

func download(ctx context.Context, url string) ([]byte, error) {
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
		return nil, statusError(resp.StatusCode)
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
