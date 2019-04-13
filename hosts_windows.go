// +build windows

package dnsproxy

import "os"

var hostsPath = os.Getenv("SystemRoot") + `\System32\drivers\etc\hosts`
