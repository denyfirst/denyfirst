//go:build !windows

package dnsclient

import (
	"fmt"
	"os"
	"strings"
)

// resolvConf is where the nameserver list lives. A variable so a test can point
// at a file it wrote, rather than at whatever the machine running the test
// happens to be configured with.
var resolvConf = "/etc/resolv.conf"

// systemResolvers reads every nameserver from resolv.conf, in order.
//
// Every one of them rather than the first, because the file lists more than one
// for exactly the reason a caller needs them: the second is there because the
// first is allowed to be unreachable. Reading only the first reported "not
// checked" for a machine whose primary resolver was down, which is a fact about
// this machine printed as a limit of the check (R7).
//
// What counts as usable, and the bound, are resolverList's — one
// implementation for every platform.
func systemResolvers() ([]string, error) {
	raw, err := os.ReadFile(resolvConf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoResolver, err)
	}

	var found []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		found = append(found, fields[1])
	}

	out := resolverList(found)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no usable nameserver line in %s", ErrNoResolver, resolvConf)
	}
	return out, nil
}
