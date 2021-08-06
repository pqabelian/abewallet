package nat

import "net"

type nat interface {
	GetExternalIPAddress() (net.IP, error)
	AddPortMapping(protocol string, localPort, remotePort int) error
	DeletePortMapping(protocol string, remotePort int) error
}
