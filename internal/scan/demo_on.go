//go:build demo

package scan

// Demo is true in the build that runs on denyfirst.dev.
//
// The gate is this constant and not the length of the list below. Written the
// other way — refuse only when a list is non-empty — a list emptied by a bad
// merge would open the deployment to the whole internet and every test would
// still pass. This way an emptied list refuses everything, which is a failure
// somebody notices in a second.
const Demo = true

// demoTargets are the hosts this project owns.
//
// Each entry covers everything beneath it, so one line admits the whole
// demonstration set as it grows. Nothing else may be added: a host somebody
// else owns is a host we are scanning on a stranger's behalf, which is the
// arrangement this build exists to end.
var demoTargets = []string{
	"denyfirst.dev",
}
