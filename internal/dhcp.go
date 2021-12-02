package rpe

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"errors"
)

type Packet []byte
type OptionCode byte
type OpCode byte
type MessageType byte

type Option struct {
	Code  OptionCode
	Value []byte
}

type NetworkEnumerator struct {
	Interfaces func() ([]net.Interface, error)
	Addrs      func(*net.Interface) ([]net.Addr, error)
}

type UDPConnection struct {
	Connection net.Conn
}

var domain string
var assignip string = "169.254.214.131"
var clientmac string = "54-B2-03-89-D3-B9"
var subnetmask net.IP = []byte{255, 255, 255, 0}
var dns net.IP = []byte{8, 8, 8, 8}
var padder [272]byte

const (
	destport	 string = "68"          // DHCP packets written to port 68

	dhcpdiscover MessageType = 1
	dhcpoffer    MessageType = 2
	dhcprequest  MessageType = 3
	dhcpdecline  MessageType = 4
	dhcpack      MessageType = 5
	dhcpnack     MessageType = 6
	dhcprelease  MessageType = 7
	dhcpinform   MessageType = 8

	bootrequest OpCode = 1
	bootreply   OpCode = 2

	End              OptionCode = 255
	OptionSubnetMask OptionCode = 1
	OptionTimeOffset OptionCode = 2

	OptionNameServer       OptionCode = 5
	OptionDomainNameServer OptionCode = 6
	OptionHostName         OptionCode = 12
	OptionDomainName       OptionCode = 15
	OptionDefaultTTL       OptionCode = 23

	OptionRequestedIPAddress   OptionCode = 50
	OptionIPLeaseTime          OptionCode = 51
	OptionDHCPMessageType      OptionCode = 53
	OptionServerIdentifier     OptionCode = 54
	OptionParameterRequestList OptionCode = 55
	OptionRenewalTime          OptionCode = 58
	OptionRebindingTime        OptionCode = 59
	OptionCLientIdentifier     OptionCode = 61
)

func SendAck(domainName string) {

	domain = domainName
	
	// DHCP packets are broadcasted.  Get broadcast address
	broadcast := getBroadcastAddr(NetPkgEnumerator())

	// Create a UDP connection
	udp := UDPConnection{}
	err := udp.Connect(broadcast, destport)
	if err != nil {
		log.Println("failed dial step ", err)
		return
	}
	defer udp.Close()

	// Initialize info for ack packet
	serverIP := net.IP.To4(net.ParseIP(getIPV4Addr(NetPkgEnumerator())))
	assignedIP := net.ParseIP(assignip)
	options := setDHCPOptions()

	// Create ack packet
	pkt := createReplyPacket(dhcpack, serverIP, assignedIP, options)

	// Write ack packet
	err = udp.Write(pkt)
	if err != nil {
		log.Println(err)
	}

}

func (udp *UDPConnection) Connect(ipaddr string, destport string) error {
	var err error
	udp.Connection, err = net.Dial("udp", ipaddr+":"+destport)
	if err != nil {
		log.Println("failed dial step ", err)
		return err
	}
	return nil
}

func (udp *UDPConnection) Write(pkt Packet) error {
	_, err := udp.Connection.Write(pkt)
	if err != nil {
		return err
	}
	return nil
}

func (udp *UDPConnection) Close() error {
	if udp.Connection == nil {
		return errors.New("no connection to close")
	}

	err := udp.Connection.Close()
	udp.Connection = nil
	return err
}

func createReplyPacket(msgType MessageType, serverId net.IP, yIAddr net.IP, opitons []Option) Packet {
	p := NewPacket(bootreply)
	p.SetXId(IntToByteArray(10392900, 4))
	p.SetFlags(IntToByteArray(32768, 2))
	p.SetYIAddr(yIAddr)
	p.SetGIAddr(net.ParseIP("0.0.0.0"))
	x, _ := net.ParseMAC(clientmac)
	p.SetCHAddr(x)
	p.AddOption(OptionDHCPMessageType, []byte{byte(msgType)})
	p.AddOption(OptionServerIdentifier, []byte(serverId))
	for _, opt := range opitons {
		p.AddOption(opt.Code, opt.Value)
	}
	p.PadToMinSize()
	return p
}

func setDHCPOptions() []Option {
	var opts []Option
	addDHCPOption(&opts, OptionSubnetMask, subnetmask.To4())
	addDHCPOption(&opts, OptionTimeOffset, IntToByteArray(0, 4))
	addDHCPOption(&opts, OptionDomainNameServer, dns.To4())
	addDHCPOption(&opts, OptionDomainName, []byte(domain))
	addDHCPOption(&opts, OptionDefaultTTL, []byte{64})
	addDHCPOption(&opts, OptionIPLeaseTime, IntToByteArray(86400, 4))
	addDHCPOption(&opts, OptionRenewalTime, IntToByteArray(43200, 4))
	addDHCPOption(&opts, OptionRebindingTime, IntToByteArray(75600, 4))
	return opts
}

func addDHCPOption(array *[]Option, code OptionCode, value []byte) {
	tmp := Option{Code: code, Value: value}
	*array = append(*array, tmp)
}

func getIPV4Addr(ne NetworkEnumerator) string {
	list, err := ne.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range list {
		if iface.Name == "Ethernet" {
			addrs, err := ne.Addrs(&iface)
			if err != nil {
				panic(err)
			}
			i := strings.Index(addrs[1].String(), "/")
			return strings.TrimSpace(addrs[1].String()[:i])
		}
	}
	return ""
}

func getBroadcastAddr(ne NetworkEnumerator) string {
	localIp := getIPV4Addr(ne)
	subnet := localIp[:strings.LastIndex(localIp, ".")]
	return subnet + ".255"
}

func (p *Packet) PadToMinSize() {
	if n := len(*p); n < 272 {
		*p = append(*p, padder[:272-n]...)
	}
}
func (p *Packet) AddOption(optCode OptionCode, value []byte) {
	*p = append((*p)[:len(*p)-1], []byte{byte(optCode), byte(len(value))}...)
	*p = append(*p, value...)
	*p = append(*p, byte(End))
}

func NewPacket(opCode OpCode) Packet {
	p := make(Packet, 241)
	p.SetOpCode(opCode)
	p.SetHType(1)                        // Ethernet
	p.SetCookie([]byte{99, 130, 83, 99}) // DHCP "Magic Cookie"
	p[240] = byte(End)

	return p
}

func IntToByteArray(num int, bytes int) []byte {
	b := make([]byte, bytes)

	if bytes == 4 {
		binary.LittleEndian.PutUint32(b, uint32(num))
	}
	if bytes == 2 {
		binary.LittleEndian.PutUint16(b, uint16(num))
	}
	return b
}

func NetPkgEnumerator() NetworkEnumerator {
	return NetworkEnumerator{
		Interfaces: net.Interfaces,
		Addrs:      (*net.Interface).Addrs,
	}
}

func (p Packet) OpCode() OpCode { return OpCode(p[0]) }
func (p Packet) HType() byte    { return p[1] }
func (p Packet) HLen() byte     { return p[2] }
func (p Packet) Hops() byte     { return p[3] }
func (p Packet) XId() []byte    { return p[4:8] }
func (p Packet) Secs() []byte   { return p[8:10] }
func (p Packet) Flags() []byte  { return p[10:12] }
func (p Packet) CIAddr() net.IP { return net.IP(p[12:16]) }
func (p Packet) YIAddr() net.IP { return net.IP(p[16:20]) }
func (p Packet) SIAddr() net.IP { return net.IP(p[20:24]) }
func (p Packet) GIAddr() net.IP { return net.IP(p[24:28]) }
func (p Packet) CHAddr() net.HardwareAddr {
	hLen := p.HLen()
	if hLen > 16 {
		hLen = 16
	}
	return net.HardwareAddr(p[28 : 28+hLen])
}
func (p Packet) Cookie() []byte { return p[236:240] }

func (p Packet) SetOpCode(c OpCode)      { p[0] = byte(c) }
func (p Packet) SetHType(hType byte)     { p[1] = hType }
func (p Packet) SetCookie(cookie []byte) { copy(p.Cookie(), cookie) }
func (p Packet) SetHops(hops byte)       { p[3] = hops }
func (p Packet) SetXId(xId []byte)       { copy(p.XId(), xId) }
func (p Packet) SetSecs(secs []byte)     { copy(p.Secs(), secs) }
func (p Packet) SetFlags(flags []byte)   { copy(p.Flags(), flags) }
func (p Packet) SetCIAddr(ip net.IP)     { copy(p.CIAddr(), ip.To4()) }
func (p Packet) SetYIAddr(ip net.IP)     { copy(p.YIAddr(), ip.To4()) }
func (p Packet) SetSIAddr(ip net.IP)     { copy(p.SIAddr(), ip.To4()) }
func (p Packet) SetGIAddr(ip net.IP)     { copy(p.GIAddr(), ip.To4()) }
func (p Packet) SetCHAddr(mac net.HardwareAddr) {
	copy(p[28:44], mac)
	p[2] = byte(len(mac))
}
