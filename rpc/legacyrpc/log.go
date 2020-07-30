package legacyrpc

import "github.com/abesuite/abec/abelog"

var log = abelog.Disabled

// UseLogger sets the package-wide logger.  Any calls to this function must be
// made before a server is created and used (it is not concurrent safe).
func UseLogger(logger abelog.Logger) {
	log = logger
}
