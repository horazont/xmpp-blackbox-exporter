package config

import (
	"fmt"
	"strings"
)

type AddressFamily string

const (
	ADDRESS_FAMILY_IPV4 AddressFamily = "ipv4"
	ADDRESS_FAMILY_IPV6 AddressFamily = "ipv6"
)

func (af AddressFamily) Validate() error {
	switch af {
	case ADDRESS_FAMILY_IPV4:
		return nil
	case ADDRESS_FAMILY_IPV6:
		return nil
	case "":
		return nil
	default:
		return fmt.Errorf("invalid address family: %#v", af)
	}
}

func (af AddressFamily) MatchesNetwork(network string) bool {
	switch af {
	case ADDRESS_FAMILY_IPV4:
		if strings.HasSuffix(network, "4") {
			return true
		}
		return false
	case ADDRESS_FAMILY_IPV6:
		if strings.HasSuffix(network, "6") {
			return true
		}
		return false
	default:
		return true
	}
}

func (af AddressFamily) Network(protocol string) string {
	switch af {
	case ADDRESS_FAMILY_IPV4:
		return protocol + "4"
	case ADDRESS_FAMILY_IPV6:
		return protocol + "6"
	default:
		return protocol
	}
}
