package nat

import (
	"net"
	"testing"
)

func TestUpnp_searchUpnpGateway(t *testing.T) {
	u := &Upnp{}
	u.searchUpnpGateway()
}

func TestUpnp_DeviceDesc(t *testing.T) {
	u := &Upnp{}
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("%v", err)
	}
	log.Infof("UPNP:\n%+v", u)
	log.Infof("IGD:\n%+v", u.IGD)
}

func TestUpnp_AddPortMapping1(t *testing.T) {
	u := &Upnp{}
	err := u.AddPortMapping("TCP", 59090, 59090)
	if err != nil {
		log.Errorf("add port mapping failed: %v", err)
	} else {
		log.Debugf("successfully add port mapping")
	}
}

func TestUpnp_AddPortMapping2(t *testing.T) {
	u := &Upnp{}
	err := u.AddPortMapping("TCP", 39090, 39090)
	if err != nil {
		log.Errorf("add port mapping failed: %v", err)
	} else {
		log.Debugf("successfully add port mapping")
	}

	err = u.AddPortMapping("TCP", 8099, 39090)
	if err != nil {
		log.Errorf("add port mapping failed: %v", err)
	} else {
		log.Debugf("successfully add port mapping")
	}
}

func TestUpnp_DeletePortMapping(t *testing.T) {
	u := &Upnp{}
	err := u.DeletePortMapping("TCP", 39090)
	if err != nil {
		log.Errorf("delete port mapping failed: %v", err)
	} else {
		log.Debugf("successfully delete port mapping")
	}
}

func TestUpnp_GetExternalIPAddress(t *testing.T) {
	u := &Upnp{}
	ip, err := u.GetExternalIPAddress()
	if err != nil {
		log.Errorf("%v", err)
	} else {
		log.Debugf("Get External IP: %v", ip.String())
	}
}

func TestUpnp_GetStatusInfo(t *testing.T) {
	u := &Upnp{}
	err := u.GetStatusInfo()
	if err != nil {
		log.Errorf("%v", err)
	}
}

func TestUpnp_GetSpecificPortMappingEntry(t *testing.T) {
	u := &Upnp{}

	err := u.DeletePortMapping("TCP", 39090)
	if err != nil {
		log.Errorf("delete port mapping failed: %v", err)
	} else {
		log.Debugf("successfully delete port mapping")
	}

	err = u.AddPortMapping("TCP", 29999, 39090)
	if err != nil {
		log.Errorf("%v", err)
	}

	err = u.GetSpecificPortMappingEntry("TCP", 39090)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func TestUpnp_GetSpecificPortMappingEntry1(t *testing.T) {
	u := &Upnp{}
	err := u.GetSpecificPortMappingEntry("TCP", 39090)
	if err != nil {
		log.Errorf("%v", err)
	}
}

func TestIsLANIP(t *testing.T) {
	localIP := "192.168.1.100"
	if isLANIP(net.ParseIP(localIP)) {
		log.Debugf("%v is LAN IP", localIP)
	} else {
		log.Debugf("%v is not LAN IP", localIP)
	}

	localIP = "202.102.94.124"
	if isLANIP(net.ParseIP(localIP)) {
		log.Debugf("%v is LAN IP", localIP)
	} else {
		log.Debugf("%v is not LAN IP", localIP)
	}

	localIP = "127.0.0.1"
	if isLANIP(net.ParseIP(localIP)) {
		log.Debugf("%v is LAN IP", localIP)
	} else {
		log.Debugf("%v is not LAN IP", localIP)
	}
}

func isLANIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	var privateIPBlocks []*net.IPNet
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
