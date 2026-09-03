//go:build !demo

package scan

// Demo is false in the ordinary build: this is the tool, and it scans what the
// person running it points it at. That is the whole product.
const Demo = false

// demoTargets is empty here and never read, because Demo gates every use of
// it. It exists so that the two builds share one set of functions rather than
// one build carrying code the other cannot compile.
var demoTargets []string

// demoHosts is empty for the same reason: there is no menu, because there is
// no restriction to build one from.
var demoHosts []DemoHost
