//go:build windows

package dnsclient

import (
	"fmt"
	"strings"
	"syscall"
)

// Where Windows records the resolvers in use.
//
// There is no resolv.conf, and no portable call that answers this. The
// registry is read rather than iphlpapi's GetNetworkParams, which would be more
// direct and would mean walking a C structure through unsafe pointers to get
// it. Everything below reads documented string values, so a mistake here is a
// resolver not found rather than a process reading the wrong memory — and a
// resolver not found is a report saying the check did not happen, which is
// where this code was before it existed.
const (
	tcpipParameters  = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	tcpip6Parameters = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
)

const (
	// maxRegistryValue bounds one value read. A nameserver list is a few
	// dozen bytes; this is generous and still refuses to allocate whatever a
	// value claims to be.
	maxRegistryValue = 4 << 10

	// maxInterfaces bounds the enumeration. A machine with more network
	// adapters than this has something else going on, and an unbounded loop
	// over a registry key is an unbounded loop.
	maxInterfaces = 64
)

// systemResolvers reads every resolver this machine is configured to ask, in
// the order it has them.
//
// All of them rather than the first, and that is the whole reason this file was
// written twice. The first attempt returned one address, picked correctly — the
// primary resolver of the live adapter — and the check still reported "not
// checked" on the machine this project is developed on, because that resolver
// belongs to a virtual adapter and does not answer. Windows had a second one
// configured for exactly that case and was using it. Asking one resolver and
// calling the result the machine's answer was the defect, not the choice of
// which one.
//
// IPv4 before IPv6, because a machine with both reaches more of the internet
// over the first and a CAA lookup should leave by the path everything else does.
//
// What counts as usable, which repeats are dropped, and the bound are
// resolverList's — one implementation for every platform, because a copy here
// could only ever be tested on a machine that happened to exercise it.
//
// Client.Server overrides all of it, for an operator who knows their own
// network better than a registry walk can.
func systemResolvers() ([]string, error) {
	var found []string
	for _, service := range []string{tcpipParameters, tcpip6Parameters} {
		found = append(found, resolversUnder(service)...)
	}

	out := resolverList(found)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no usable nameserver under %s in the registry",
			ErrNoResolver, tcpipParameters)
	}
	return out, nil
}

// resolversUnder collects the nameservers under one protocol's parameters.
func resolversUnder(service string) []string {
	var out []string

	if key, err := openKey(service); err == nil {
		// A value here is one an administrator set for the whole machine, so
		// it comes before anything an adapter was handed.
		out = append(out, addresses(stringValue(key, "NameServer"))...)
		syscall.RegCloseKey(key)
	}

	interfaces, err := openKey(service + `\Interfaces`)
	if err != nil {
		return out
	}
	defer syscall.RegCloseKey(interfaces)

	for _, name := range subkeys(interfaces) {
		adapter, err := openKey(service + `\Interfaces\` + name)
		if err != nil {
			continue
		}

		// Static before DHCP, for the same reason as above: one was typed by
		// somebody and the other arrived.
		out = append(out, addresses(stringValue(adapter, "NameServer"))...)
		out = append(out, addresses(stringValue(adapter, "DhcpNameServer"))...)
		syscall.RegCloseKey(adapter)
	}
	return out
}

// addresses splits a registry nameserver list, which Windows writes separated by
// spaces or by commas depending on where the value came from.
//
// It splits and nothing else. Deciding which of them can be dialled is
// resolverList's job, and doing it twice is how the two answers come to differ.
func addresses(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})
}

func openKey(path string) (syscall.Handle, error) {
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE, wide, 0, syscall.KEY_READ, &key,
	); err != nil {
		return 0, err
	}
	return key, nil
}

// stringValue reads one string value, or returns empty for anything that is
// not one.
//
// The size is asked for before the value is read, so a value longer than the
// buffer is a refusal rather than a truncation. A truncated address is worse
// than no address: it parses as something else or as nothing, and either way
// the reason is invisible.
func stringValue(key syscall.Handle, name string) string {
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}

	var kind, size uint32
	if err := syscall.RegQueryValueEx(key, wide, nil, &kind, nil, &size); err != nil {
		return ""
	}
	if size == 0 || size > maxRegistryValue {
		return ""
	}
	if kind != syscall.REG_SZ && kind != syscall.REG_EXPAND_SZ {
		return ""
	}

	buf := make([]byte, size)
	if err := syscall.RegQueryValueEx(key, wide, nil, &kind, &buf[0], &size); err != nil {
		return ""
	}
	if size > uint32(len(buf)) {
		return ""
	}
	return utf16BytesToString(buf[:size])
}

func subkeys(key syscall.Handle) []string {
	var out []string

	// A GUID is thirty-eight characters. This is room for anything the
	// registry will hold under that key.
	name := make([]uint16, 256)

	for i := uint32(0); len(out) < maxInterfaces; i++ {
		length := uint32(len(name))
		if err := syscall.RegEnumKeyEx(key, i, &name[0], &length, nil, nil, nil, nil); err != nil {
			// Including ERROR_NO_MORE_ITEMS, which is how the list ends.
			break
		}
		out = append(out, syscall.UTF16ToString(name[:length]))
	}
	return out
}

// utf16BytesToString decodes the bytes the registry returned.
//
// Done here rather than by pointing a uint16 slice at the same memory, which
// is the usual trick and needs unsafe. A nameserver list is a few dozen bytes;
// the copy costs nothing worth having unsafe in this package for.
func utf16BytesToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	wide := make([]uint16, len(b)/2)
	for i := range wide {
		wide[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return syscall.UTF16ToString(wide)
}
