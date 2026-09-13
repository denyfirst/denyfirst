package rawhello

// Suite is one value this package offers, under the name the IANA registry
// gives it.
//
// The names are the registry's, letter for letter, because internal/policy
// grades a suite by its name: a rule matching "EXPORT" or "NULL" has to be shown
// the word, and crypto/tls.CipherSuiteName knows none of these and returns a
// hexadecimal number instead.
type Suite struct {
	ID   uint16
	Name string
}

// Export is every export-grade suite in the registry.
//
// Key sizes deliberately limited in the 1990s for export rules. FREAK and
// Logjam are the reason a server still accepting one is graded insecure rather
// than merely old.
var Export = []Suite{
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
	{0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"},
	{0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
	{0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"},
	{0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"},
}

// Null is the NULL-cipher suites a server is realistically configured with:
// authenticated, and sent in the clear.
//
// The elliptic-curve ones need the supported_groups extension to be chosen at
// all, which is why a hello offering this list carries extensions.
var Null = []Suite{
	{0x0001, "TLS_RSA_WITH_NULL_MD5"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA"},
	{0x003B, "TLS_RSA_WITH_NULL_SHA256"},
	{0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"},
	{0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"},
	{0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"},
	{0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"},
}

// SSL3 is what an SSL 3.0 hello offers: the suites a server of that era would
// choose among, with the export and non-elliptic NULL suites included.
//
// Broad on purpose. The question is whether the server speaks SSL 3.0 at all,
// and a hello offering only suites the server was not configured with would be
// refused for a reason that has nothing to do with the version — which is the
// same ambiguity LimitCipherSuitesOffered describes for Go's own client.
var SSL3 = append([]Suite{
	{0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
	{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
	{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
	{0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
	{0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
	{0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
	{0x0001, "TLS_RSA_WITH_NULL_MD5"},
	{0x0002, "TLS_RSA_WITH_NULL_SHA"},
}, Export...)

// IDs is a list of suites as the values a hello carries.
func IDs(suites []Suite) []uint16 {
	out := make([]uint16, 0, len(suites))
	for _, s := range suites {
		out = append(out, s.ID)
	}
	return out
}

// Name is the registry name of a suite this package offers, or empty.
//
// Only suites offered here. A server answering with anything else chose a
// suite it was not offered, and a caller should not be given a name that makes
// that look like an ordinary answer.
func Name(id uint16) string {
	for _, list := range [][]Suite{SSL3, Null} {
		for _, s := range list {
			if s.ID == id {
				return s.Name
			}
		}
	}
	return ""
}
