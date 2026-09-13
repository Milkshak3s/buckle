package ship

import (
	"errors"
	"os"
	"os/exec"
	"regexp"

	"buckle/internal/wire"
)

var platformUUID = regexp.MustCompile(`"IOPlatformUUID" = "([0-9A-Fa-f-]{36})"`)

// HostIdentity is this Mac's hardware UUID (stable across buckle reinstalls) and hostname.
func HostIdentity() (wire.Host, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return wire.Host{}, err
	}
	m := platformUUID.FindSubmatch(out)
	if m == nil {
		return wire.Host{}, errors.New("ioreg output has no IOPlatformUUID")
	}
	name, err := os.Hostname()
	if err != nil {
		return wire.Host{}, err
	}
	return wire.Host{UUID: string(m[1]), Name: name}, nil
}
