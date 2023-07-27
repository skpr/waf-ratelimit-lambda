package iputils

import (
	"fmt"
	"strings"
)

// GetIPfromCIDR returns the IP address from a CIDR notation string.
func GetIPfromCIDR(cidr string) (string, error) {
	sl := strings.Split(cidr, "/")

	if len(sl) != 2 {
		return "", fmt.Errorf("invalid CIDR notation: %s", cidr)
	}

	if sl[1] != "32" {
		return "", fmt.Errorf("invalid CIDR notation (needs to be x.x.x.x/32): %s", cidr)
	}

	return sl[0], nil
}
