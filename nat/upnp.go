package nat

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

/*
Reference:
https://en.wikipedia.org/wiki/Universal_Plug_and_Play
https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol
http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v1-Device.pdf
http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf
*/

const (
	ssdpUDP4Addr = "239.255.255.250:1900"

	// maxWaitTime should be equal to ssdpDiscoverMsgV1/V2 MX value.
	maxWaitTime       = 3 // in second
	ssdpDiscoverMsgV1 = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n" +
		"MAN: \"ssdp:discover\"\r\n" + "MX: 3\r\n\r\n"

	ssdpDiscoverMsgV2 = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"ST: urn:schemas-upnp-org:service:WANIPConnection:2\r\n" +
		"MAN: \"ssdp:discover\"\r\n" + "MX: 3\r\n\r\n"

	WANIPCONNECTION_V1 = "urn:schemas-upnp-org:service:WANIPConnection:1"
	WANIPCONNECTION_V2 = "urn:schemas-upnp-org:service:WANIPConnection:2"

	soapPrefix = xml.Header + `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"> `
	soapSuffix = `</SOAP-ENV:Envelope>`
)

type Gateway struct {
	Name          string
	Cache         string
	ST            string
	USN           string
	Host          string //ip:port
	DeviceDescUrl string
}

type Upnp struct {
	LocalAddr   string
	IGDPVersion int      //Internet Gateway Device Protocol Version
	IGD         *Gateway // Internet Gateway Device
	CtrlUrl     string
}

type xmlNode struct {
	name    string
	content string
	attr    map[string]string
	child   []xmlNode
}

func (xn *xmlNode) addChild(n xmlNode) {
	xn.child = append(xn.child, n)
}

func (xn *xmlNode) buildXML() string {
	buf := bytes.NewBufferString("<")
	buf.WriteString(xn.name)
	for key, value := range xn.attr {
		buf.WriteString(" ")
		buf.WriteString(key + "=" + value)
	}
	buf.WriteString(">" + xn.content)

	for _, n := range xn.child {
		buf.WriteString(n.buildXML())
	}
	buf.WriteString("</" + xn.name + ">")
	return buf.String()
}

func getLocalInternetIP() (string, error) {
	conn, err := net.Dial("udp", "google.com:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0], nil
}

/*
Before call API function, please run searchUnpGateway() function to init upnp info.
return:
version: 0   cannot search gateway to support upnp
version: 1   search gateway to support upnp with version 1
version: 2   search gateway to support upnp with version 2
*/
func (u *Upnp) searchUpnpGateway() error {
	remoteAddr, err := net.ResolveUDPAddr("udp", ssdpUDP4Addr)
	if err != nil {
		log.Errorf("resolve udp address for %s error: %v", ssdpUDP4Addr, err)
		return err
	}
	localInternetIP, _ := getLocalInternetIP()
	u.LocalAddr = localInternetIP
	if localInternetIP == "" {
		return errors.New("get local internet ip address failed")
	}
	localAddr, err := net.ResolveUDPAddr("udp", localInternetIP+":")

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Errorf("listen udp for local address failed: %v", err)
		return err
	}
	defer conn.Close()

	if u.checkIgdVersion(ssdpDiscoverMsgV1, conn, remoteAddr) {
		u.IGDPVersion = 1
	} else if u.checkIgdVersion(ssdpDiscoverMsgV2, conn, remoteAddr) {
		u.IGDPVersion = 2
	} else {
		return errors.New("not support IGD")
	}
	return nil
}

// check Internet Gateway Device version
func (u *Upnp) checkIgdVersion(versionString string, conn *net.UDPConn, remoteAddr *net.UDPAddr) bool {
	_, err := conn.WriteToUDP([]byte(versionString), remoteAddr)
	if err != nil {
		log.Errorf("send request to address %s failed: %v", ssdpUDP4Addr, err)
		return false
	}

	now := time.Now()
	timeOut := now.Add(maxWaitTime * time.Second)

	buf := make([]byte, 2048)
	conn.SetReadDeadline(timeOut)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Errorf("cannot get response from address %s with error: %v for version string %s", ssdpUDP4Addr, err, versionString)
	} else {
		response := string(buf[:n])
		log.Debugf("version string %s get response:\n %v", versionString, response)
		u.resolveSearchUpnpGatewayResponse(response)
		err = u.getUpnpInfo() // update Upnp.CtrUrl
		if err != nil {
			log.Errorf("get gateway information failed: %v", err)
			return false
		}
	}
	return true
}

func (u *Upnp) resolveSearchUpnpGatewayResponse(response string) {
	u.IGD = &Gateway{}

	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		// separate to two strings by the first :
		nameValues := strings.SplitAfterN(line, ":", 2)
		if len(nameValues) < 2 {
			continue
		}
		switch strings.ToUpper(strings.Trim(strings.Split(nameValues[0], ":")[0], " ")) {
		case "ST":
			u.IGD.ST = nameValues[1]
		case "CACHE-CONTROL":
			u.IGD.Cache = nameValues[1]
		case "LOCATION":
			urls := strings.Split(strings.Split(nameValues[1], "//")[1], "/")
			u.IGD.Host = urls[0]
			u.IGD.DeviceDescUrl = "/" + urls[1]
		case "SERVER":
			u.IGD.Name = nameValues[1]
		case "USN":
			u.IGD.USN = nameValues[1]
		default:
		}
	}
}

func (u *Upnp) buildSoapHeader(action string) http.Header {
	log.Debugf("IDGPVersion: %d", u.IGDPVersion)
	if u.IGDPVersion != 1 && u.IGDPVersion != 2 {
		return nil
	}
	header := http.Header{}
	header.Set("Accept", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2")
	var soapAction string
	if u.IGDPVersion == 1 {
		soapAction = `"urn:schemas-upnp-org:service:WANIPConnection:1#` + action + `"`
	} else {
		soapAction = `"urn:schemas-upnp-org:service:WANIPConnection:2#` + action + `"`
	}
	header.Set("SOAPAction", soapAction)
	header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	header.Set("Connection", "Close")
	header.Set("Content-Length", "")
	log.Debugf("header: %+v", header)
	return header
}

func (u *Upnp) buildSoapBodyString(action string, params interface{}) (string, error) {
	bodyNode := xmlNode{name: `SOAP-ENV:Body`}

	childName := `m:` + action
	var childAttrValue string
	if u.IGDPVersion == 1 {
		childAttrValue = `"urn:schemas-upnp-org:service:WANIPConnection:1"`
	} else if u.IGDPVersion == 2 {
		childAttrValue = `"urn:schemas-upnp-org:service:WANIPConnection:2"`
	} else {
		return "", errors.New("Upnp version is wrong")
	}

	childNode := xmlNode{name: childName, attr: map[string]string{"xmlns:m": childAttrValue}}
	s := reflect.ValueOf(params).Elem()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		log.Debugf("%s, %s = %v", f.Type(), s.Type().Field(i).Name, f.Interface())
		name := s.Type().Field(i).Name
		content := f.Interface().(string)
		grandson := xmlNode{}
		grandson.name = name
		grandson.content = content
		childNode.addChild(grandson)
	}

	bodyNode.addChild(childNode)
	bodyStr := bodyNode.buildXML()
	log.Debugf("SOAP body string: %v", bodyStr)
	return bodyStr, nil
}

/*
Request Example:
<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>39090</NewExternalPort>
      <NewInternalPort>39090</NewInternalPort>
      <NewProtocol>TCP</NewProtocol>
      <NewEnabled>1</NewEnabled>
      <NewInternalClient>10.1.0.111</NewInternalClient>
      <NewLeaseDuration>0</NewLeaseDuration>
      <NewPortMappingDescription>Gravity P2P by DCG</NewPortMappingDescription>
      <NewRemoteHost/>
    </m:AddPortMapping>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>

Successful response:
<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
*/
// protocol supports "tcp" and "udp"
func (u *Upnp) AddPortMapping(protocol string, localPort, remotePort int) error {
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("device doesn't support upnp: %v", err)
		return err
	}
	action := "AddPortMapping"
	// Request parameter structure.
	params := &struct {
		NewExternalPort           string
		NewInternalPort           string
		NewProtocol               string
		NewEnabled                string
		NewInternalClient         string
		NewLeaseDuration          string
		NewPortMappingDescription string
		NewRemoteHost             string
	}{}

	params.NewInternalPort = strconv.Itoa(localPort)
	params.NewExternalPort = strconv.Itoa(remotePort)
	params.NewInternalClient = u.LocalAddr
	params.NewEnabled = "1"
	params.NewLeaseDuration = "0"
	params.NewPortMappingDescription = "Abelian P2P by Abelian"
	params.NewProtocol = protocol
	params.NewRemoteHost = ""

	bodyStr, err := u.buildSoapBodyString(action, params)
	if err != nil {
		log.Errorf("build body string failed: %v", err)
		return err
	}
	requestStr := soapPrefix + bodyStr + soapSuffix

	header := u.buildSoapHeader(action)
	log.Debugf("request URL: %s", "http://"+u.IGD.Host+u.CtrlUrl)
	request, _ := http.NewRequest("POST", "http://"+u.IGD.Host+u.CtrlUrl,
		strings.NewReader(requestStr))
	request.Header = header
	log.Debugf("request header: %+v", request.Header)
	request.Header.Set("Content-Length", strconv.Itoa(len(requestStr)))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Debugf("http request failed: %v", err)
		return err
	}
	defer response.Body.Close()
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		log.Debugf("successfully add port mapping with response: \n%v", string(resultBody))
		return nil
	} else {
		log.Errorf("failed to add port mapping with response: \n%v", string(resultBody))
	}
	return errors.New("get http response error for AddPortMapping")
}

func (u *Upnp) GetExternalIPAddress() (net.IP, error) {
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("device doesn't support upnp: %v", err)
		return nil, err
	}

	action := "GetExternalIPAddress"
	params := &struct{}{}

	bodyStr, err := u.buildSoapBodyString(action, params)
	if err != nil {
		log.Errorf("build body string failed: %v", err)
		return nil, err
	}
	requestStr := soapPrefix + bodyStr + soapSuffix
	header := u.buildSoapHeader(action)
	log.Debugf("request URL: %s", "http://"+u.IGD.Host+u.CtrlUrl)
	request, _ := http.NewRequest("POST", "http://"+u.IGD.Host+u.CtrlUrl,
		strings.NewReader(requestStr))
	request.Header = header
	log.Debugf("request header: %+v", request.Header)
	request.Header.Set("Content-Length", strconv.Itoa(len(requestStr)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Debugf("http request failed: %v", err)
		return nil, err
	}
	defer response.Body.Close()
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		log.Debugf("successfully get external IP with response: \n%v", string(resultBody))
		externalIP := u.resolveExternalIPAddressResponse(string(resultBody))
		return net.ParseIP(externalIP), nil
	} else {
		log.Errorf("failed to get external IP with response: \n%v", string(resultBody))
	}
	return nil, errors.New("get http response error for GetExternalIPAddress")
}

func (u *Upnp) DeletePortMapping(protocol string, remotePort int) error {
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("device doesn't support upnp: %v", err)
		return err
	}
	action := "DeletePortMapping"
	params := &struct {
		NewExternalPort string
		NewProtocol     string
		NewRemoteHost   string
	}{}
	params.NewExternalPort = strconv.Itoa(remotePort)
	params.NewProtocol = protocol
	params.NewRemoteHost = ""
	bodyStr, err := u.buildSoapBodyString(action, params)
	if err != nil {
		log.Errorf("build body string failed: %v", err)
		return err
	}
	requestStr := soapPrefix + bodyStr + soapSuffix
	header := u.buildSoapHeader(action)
	log.Debugf("request URL: %s", "http://"+u.IGD.Host+u.CtrlUrl)
	request, _ := http.NewRequest("POST", "http://"+u.IGD.Host+u.CtrlUrl,
		strings.NewReader(requestStr))
	request.Header = header
	log.Debugf("request header: %+v", request.Header)
	request.Header.Set("Content-Length", strconv.Itoa(len(requestStr)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Debugf("http request failed: %v", err)
		return err
	}
	defer response.Body.Close()
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		log.Debugf("successfully delete port mapping with response: \n%v", string(resultBody))
		return nil
	} else {
		log.Errorf("failed to delete port mapping with response: \n%v", string(resultBody))
	}
	return errors.New("get http response error for DeletePortMapping")
}

/*
response example:
<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
<u:GetStatusInfoResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewConnectionStatus>Connected</NewConnectionStatus><NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>0 Days, 00:16:40</NewUptime></u:GetStatusInfoResponse></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
*/
func (u *Upnp) GetStatusInfo() error {
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("device doesn't support upnp: %v", err)
		return err
	}
	action := "GetStatusInfo"
	params := &struct {
	}{}
	bodyStr, err := u.buildSoapBodyString(action, params)
	if err != nil {
		log.Errorf("build body string failed: %v", err)
		return err
	}
	requestStr := soapPrefix + bodyStr + soapSuffix
	header := u.buildSoapHeader(action)
	request, _ := http.NewRequest("POST", "http://"+u.IGD.Host+u.CtrlUrl,
		strings.NewReader(requestStr))
	request.Header = header
	log.Debugf("request header: %+v", request.Header)
	request.Header.Set("Content-Length", strconv.Itoa(len(requestStr)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Debugf("http request failed: %v", err)
		return err
	}
	defer response.Body.Close()
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		log.Debugf("successfully get status info with response: \n%v", string(resultBody))
		return nil
	} else {
		log.Errorf("failed to get status info with response: \n%v", string(resultBody))
	}
	return errors.New("get http response error for GetStatusInfo")
}

type portMappingEntry struct {
	NewInternalPort           string
	NewInternalClient         string
	NewEnabled                string
	NewPortMappingDescription string
	NewLeaseDuration          string
}

func (u *Upnp) GetSpecificPortMappingEntry(protocol string, remotePort int) error {
	err := u.searchUpnpGateway()
	if err != nil {
		log.Errorf("device doesn't support upnp: %v", err)
		return err
	}
	action := "GetSpecificPortMappingEntry"
	params := &struct {
		NewRemoteHost   string
		NewExternalPort string
		NewProtocol     string
	}{}
	params.NewRemoteHost = ""
	params.NewExternalPort = strconv.Itoa(remotePort)
	params.NewProtocol = protocol

	bodyStr, err := u.buildSoapBodyString(action, params)
	if err != nil {
		log.Errorf("build body string failed: %v", err)
		return err
	}
	requestStr := soapPrefix + bodyStr + soapSuffix
	header := u.buildSoapHeader(action)
	log.Debugf("request URL: %s", "http://"+u.IGD.Host+u.CtrlUrl)
	request, _ := http.NewRequest("POST", "http://"+u.IGD.Host+u.CtrlUrl,
		strings.NewReader(requestStr))
	request.Header = header
	log.Debugf("request header: %+v", request.Header)
	request.Header.Set("Content-Length", strconv.Itoa(len(requestStr)))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Debugf("http request failed: %v", err)
		return err
	}
	defer response.Body.Close()
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		log.Debugf("successfully get specific port mapping entry with response: \n%v", string(resultBody))
		entry := u.resolveSpecificPortMappingResponse(string(resultBody))
		s := reflect.ValueOf(entry).Elem()
		for i := 0; i < s.NumField(); i++ {
			f := s.Field(i)
			log.Debugf("%s, %s = %v", f.Type(), s.Type().Field(i).Name, f.Interface())
		}
		return nil
	} else {
		log.Errorf("failed to get specific port mapping entry with response: \n%v", string(resultBody))
	}
	return errors.New("get http response error for specific port mapping entry")
}

// Get Gateway Device Description Information
func (u *Upnp) getUpnpInfo() error {
	//request header
	header := http.Header{}
	header.Set("Accept", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2")
	header.Set("User-Agent", "preston")
	header.Set("Host", u.IGD.Host)
	header.Set("Connection", "keep-alive")

	//request
	log.Debugf("request URL: %s", "http://"+"http://"+u.IGD.Host+u.IGD.DeviceDescUrl)
	request, err := http.NewRequest("GET", "http://"+u.IGD.Host+u.IGD.DeviceDescUrl, nil)
	if err != nil {
		return err
	}
	request.Header = header

	response, _ := http.DefaultClient.Do(request)
	resultBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		u.resolveGatewayInfoResponse(string(resultBody)) // update Upnp information
		log.Debugf("response:\n%v", string(resultBody))
		return nil
	} else {
		log.Errorf("failed to get upnp info with response: \n%v", string(resultBody))
	}
	return errors.New("get http response error for device description")
}

func (u *Upnp) resolveGatewayInfoResponse(response string) {
	inputReader := strings.NewReader(response)
	lastLabel := ""
	ISUpnpServer := false
	IScontrolURL := false
	var controlURL string //`controlURL`
	// var eventSubURL string //`eventSubURL`
	// var SCPDURL string     //`SCPDURL`

	decoder := xml.NewDecoder(inputReader)
	for t, err := decoder.Token(); err == nil && !IScontrolURL; t, err = decoder.Token() {
		switch token := t.(type) {
		case xml.StartElement:
			if ISUpnpServer {
				name := token.Name.Local
				lastLabel = name
			}
			//log.Debugf("token name: %s", token.Name.Local)
		case xml.EndElement:
			//log.Debugf("token of %s end", token.Name.Local)
		case xml.CharData:
			content := string([]byte(token))
			//log.Debugf("token content: %s ", content)

			if content == WANIPCONNECTION_V1 || content == WANIPCONNECTION_V2 {
				ISUpnpServer = true
				continue
			}
			//urn:upnp-org:serviceId:WANIPConnection
			if ISUpnpServer {
				switch lastLabel {
				case "controlURL":
					controlURL = content
					IScontrolURL = true
				}
			}
		default:
			// ...
		}
	}
	u.CtrlUrl = controlURL
}

func (u *Upnp) resolveExternalIPAddressResponse(response string) string {
	inputReader := strings.NewReader(response)
	decoder := xml.NewDecoder(inputReader)
	ISexternalIP := false
	for t, err := decoder.Token(); err == nil; t, err = decoder.Token() {
		switch token := t.(type) {

		case xml.StartElement:
			name := token.Name.Local
			if name == "NewExternalIPAddress" {
				ISexternalIP = true
			}

		case xml.EndElement:

		case xml.CharData:
			if ISexternalIP == true {
				externalIP := string([]byte(token))
				return externalIP
			}
		default:
			// ...
		}
	}
	return ""
}

func (u *Upnp) resolveSpecificPortMappingResponse(response string) *portMappingEntry {
	entry := portMappingEntry{}
	inputReader := strings.NewReader(response)
	decoder := xml.NewDecoder(inputReader)
	IsNewInternalPort := false
	IsNewInternalClient := false
	IsNewEnabled := false
	IsNewPortMappingDescription := false
	IsNewLeaseDuration := false
	for t, err := decoder.Token(); err == nil; t, err = decoder.Token() {
		switch token := t.(type) {

		case xml.StartElement:
			name := token.Name.Local
			if name == "NewInternalPort" {
				IsNewInternalPort = true
			}
			if name == "NewInternalClient" {
				IsNewInternalClient = true
			}
			if name == "NewEnabled" {
				IsNewEnabled = true
			}
			if name == "NewPortMappingDescription" {
				IsNewPortMappingDescription = true
			}
			if name == "NewLeaseDuration" {
				IsNewLeaseDuration = true
			}

		case xml.EndElement:

		case xml.CharData:
			if IsNewInternalPort == true {
				entry.NewInternalPort = string([]byte(token))
				IsNewInternalPort = false
			}
			if IsNewInternalClient == true {
				entry.NewInternalClient = string([]byte(token))
				IsNewInternalClient = false
			}
			if IsNewEnabled == true {
				entry.NewEnabled = string([]byte(token))
				IsNewEnabled = false
			}
			if IsNewPortMappingDescription == true {
				entry.NewPortMappingDescription = string([]byte(token))
				IsNewPortMappingDescription = false
			}
			if IsNewLeaseDuration == true {
				entry.NewLeaseDuration = string([]byte(token))
				IsNewLeaseDuration = false
			}
		default:
			// ...
		}
	}
	return &entry
}
