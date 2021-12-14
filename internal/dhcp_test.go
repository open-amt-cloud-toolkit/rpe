package rpe

import (
	//"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"net"
)
func TestConnect(t *testing.T) {
	_, client := net.Pipe()

	udp := UDPConnection{Connection: client}
	err := udp.Connect("", "")
	defer udp.Close()
	assert.NoError(t, err)
}

func TestWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	udp := UDPConnection{
		Connection: client,
	}
	defer udp.Close() // should close client pipe
	pkt := NewPacket(bootReply)
	go func() {
		err := udp.Write(pkt)
		assert.NoError(t, err)
	}()

	
	readbuff := make([]byte, 65535)
	n, err := server.Read(readbuff)
	assert.Equal(t, len(pkt), len(readbuff[:n]))
	assert.NoError(t, err)
}

func TestIntToByteArray(t *testing.T) {
	want := []byte{128, 81, 1, 0}

	rcvd := IntToByteArray(86400, 4)

	assert.Equal(t, want, rcvd)
}
func Test2IntToByteArray(t *testing.T) {
	want := []byte{0, 128}

	rcvd := IntToByteArray(32768, 2)

	assert.Equal(t, want, rcvd)
}
func Test3IntToByteArray(t *testing.T) {
	want := []byte(nil)

	rcvd := IntToByteArray(32768, 3)

	assert.Equal(t, want, rcvd)
}

func TestNewPacket(t *testing.T) {
	want_opcode := byte(bootReply)
	want_htype := byte(1)
	want_cookie := []byte{99, 130, 83, 99}
	want_pktLen := 241
	want_lastbyte := End

	rcvd := NewPacket(bootReply)

	assert.Equal(t, want_opcode, rcvd[0])
	assert.Equal(t, want_htype, rcvd[1])
	assert.Equal(t, want_cookie, []byte(rcvd[236:240]))
	assert.Equal(t, want_pktLen, len(rcvd))
	assert.Equal(t, want_lastbyte, End)
}

func TestAddDHCPOption(t *testing.T) {
	rcvd := []Option{}
	want := []Option{}

	want = append(want, Option{Code: OptionDefaultTTL, Value: []byte{64}})
	addDHCPOption(&rcvd, OptionDefaultTTL, []byte{64})

	assert.Equal(t, want, rcvd)
}

func TestSetDHCPOption(t *testing.T) {
	want := []Option{}
	want = append(want, Option{Code: OptionSubnetMask, Value: subnetMask.To4()})
	want = append(want, Option{Code: OptionTimeOffset, Value: IntToByteArray(0, 4)})
	want = append(want, Option{Code: OptionDomainNameServer, Value: dns.To4()})
	want = append(want, Option{Code: OptionDomainName, Value: []byte(domain)})
	want = append(want, Option{Code: OptionDefaultTTL, Value: []byte{64}})
	want = append(want, Option{Code: OptionIPLeaseTime, Value: IntToByteArray(86400, 4)})
	want = append(want, Option{Code: OptionRenewalTime, Value: IntToByteArray(43200, 4)})
	want = append(want, Option{Code: OptionRebindingTime, Value: IntToByteArray(75600, 4)})

	rcvd, _ := setDHCPOptions()

	assert.Equal(t, want, rcvd)
}

func TestAddOption(t *testing.T) {
	tstIP := "1.1.1.1"
	p := NewPacket(bootReply)
	p.AddOption(OptionServerIdentifier, net.IP.To4(net.ParseIP(tstIP)))
	i := len(p) - 5

	want := tstIP
	rcvd := net.IP(p[i : i+4]).String()

	assert.Equal(t, want, rcvd)
}

func TestPadToMinSize(t *testing.T) {
	p := NewPacket(bootReply)

	want := 272
	p.PadToMinSize()

	assert.Equal(t, want, len(p))
}

func TestConsts(t *testing.T) {
	wantPort := "68"
	assert.Equal(t, wantPort, destPort)

	wantMsgType := MessageType(1) 
	assert.Equal(t, wantMsgType, dhcpDiscover)
	wantMsgType = MessageType(2) 
	assert.Equal(t, wantMsgType, dhcpOffer)
	wantMsgType = MessageType(3) 
	assert.Equal(t, wantMsgType, dhcpRequest)
	wantMsgType = MessageType(4) 
	assert.Equal(t, wantMsgType, dhcpDecline)
	wantMsgType = MessageType(5) 
	assert.Equal(t, wantMsgType, dhcpAck)
	wantMsgType = MessageType(6) 
	assert.Equal(t, wantMsgType, dhcpNack)
	wantMsgType = MessageType(7) 
	assert.Equal(t, wantMsgType, dhcpRelease)
	wantMsgType = MessageType(8) 
	assert.Equal(t, wantMsgType, dhcpInform)

	wantOpCode := OptionCode(255)
	assert.Equal(t, wantOpCode, End)
	wantOpCode = OptionCode(1)
	assert.Equal(t, wantOpCode, OptionSubnetMask)
	wantOpCode = OptionCode(2)
	assert.Equal(t, wantOpCode, OptionTimeOffset)
	wantOpCode = OptionCode(5)
	assert.Equal(t, wantOpCode, OptionNameServer)
	wantOpCode = OptionCode(6)
	assert.Equal(t, wantOpCode, OptionDomainNameServer)
	wantOpCode = OptionCode(12)
	assert.Equal(t, wantOpCode, OptionHostName)
	wantOpCode = OptionCode(15)
	assert.Equal(t, wantOpCode, OptionDomainName)
	wantOpCode = OptionCode(23)
	assert.Equal(t, wantOpCode, OptionDefaultTTL)
	wantOpCode = OptionCode(50)
	assert.Equal(t, wantOpCode, OptionRequestedIPAddress)
	wantOpCode = OptionCode(51)
	assert.Equal(t, wantOpCode, OptionIPLeaseTime)
	wantOpCode = OptionCode(53)
	assert.Equal(t, wantOpCode, OptionDHCPMessageType)
	wantOpCode = OptionCode(54)
	assert.Equal(t, wantOpCode, OptionServerIdentifier)
	wantOpCode = OptionCode(55)
	assert.Equal(t, wantOpCode, OptionParameterRequestList)
	wantOpCode = OptionCode(58)
	assert.Equal(t, wantOpCode, OptionRenewalTime)
	wantOpCode = OptionCode(59)
	assert.Equal(t, wantOpCode, OptionRebindingTime)
	wantOpCode = OptionCode(61)
	assert.Equal(t, wantOpCode, OptionCLientIdentifier)
}

func TestNetPkgEnumerator(t *testing.T) {
	want := NetworkEnumerator{
		Interfaces: net.Interfaces,
		Addrs:      (*net.Interface).Addrs,
	}
	rcvd := NetPkgEnumerator()

	assert.IsType(t, want.Interfaces, rcvd.Interfaces)
	assert.IsType(t, want.Addrs, rcvd.Addrs)
}


func TestChkSetsGets(t *testing.T) {
	yiaddr := "10.20.30.5"
	giaddr := "0.0.0.0"
	chaddr := "54:b2:03:89:d3:b9"
	tstIP := "1.1.1.1"

	p := NewPacket(2) // 2 - bootreply
	p.SetOpCode(1)    // 1 - bootrequest
	p.SetHType(2)
	p.SetHops(1)
	p.SetXId(IntToByteArray(10392900, 4))
	p.SetSecs([]byte{1, 1})
	p.SetFlags(IntToByteArray(32768, 2))
	p.SetCIAddr(net.IP.To4(net.ParseIP(tstIP)))
	p.SetYIAddr(net.ParseIP(yiaddr))
	p.SetSIAddr(net.IP.To4(net.ParseIP(tstIP)))
	p.SetGIAddr(net.ParseIP(giaddr))
	x, _ := net.ParseMAC(chaddr)
	p.SetCHAddr(x)
	p.SetCookie([]byte{99, 130, 83, 99})
	p.PadToMinSize()

	assert.Equal(t, OpCode(1), p.OpCode()) // 2 - bootrequest
	assert.Equal(t, byte(2), p.HType())    // 1 - ethernet
	assert.Equal(t, byte(6), p.HLen())     // 6 - length of MAC
	assert.Equal(t, byte(1), p.Hops())
	assert.Equal(t, []byte{68, 149, 158, 0}, p.XId()) // arbitrary transaction id of 10392900
	assert.Equal(t, []byte{1, 1}, p.Secs())
	assert.Equal(t, []byte{0, 128}, p.Flags()) // flag value of  32768
	assert.Equal(t, "1.1.1.1", p.CIAddr().String())
	assert.Equal(t, yiaddr, p.YIAddr().String())
	assert.Equal(t, "1.1.1.1", p.SIAddr().String())
	assert.Equal(t, giaddr, p.GIAddr().String())
	assert.Equal(t, chaddr, p.CHAddr().String())
	assert.Equal(t, []byte{99, 130, 83, 99}, p.Cookie())
}


var tstIP = "10.20.30.34"
var tstBroadcast = "10.20.30.255"
type mockIPV4Addr struct {
}

type mockIPV6Addr struct {
}

func (mn mockIPV4Addr) Network() string {
	return "tcp"
}
func (ma mockIPV4Addr) String() string {
	return tstIP+"/24"
}

func (mn mockIPV6Addr) Network() string {
	return "tcp"
}
func (ma mockIPV6Addr) String() string {
	return "fe80::a853:f61a:b1b6:842/64"
}

func TestSendAck(t *testing.T) {
	assert.Equal(t, nil, SendAck("test.com"))

}

func TestGetIPV4Addr(t *testing.T) {

	//create the mock Interfaces list
	parsedMac, _ := net.ParseMAC("DE:AD:BE:EF:FF:FF")
	myMockInterfaces := []net.Interface{
		{
			Index:        0,
			MTU:          5,
			Name:         "Ethernet",
			HardwareAddr: parsedMac,
			Flags:        net.FlagUp,
		},
	}

	//create the mock Interface addresses
	myMockIPV4Addr := mockIPV4Addr{}
	myMockIPV6Addr := mockIPV6Addr{}

	//now create a network enumerator
	myMockNetEnum := NetworkEnumerator{
		Interfaces: func() ([]net.Interface, error) { return myMockInterfaces, nil },
		Addrs:      func(*net.Interface) ([]net.Addr, error) { return []net.Addr{myMockIPV6Addr, myMockIPV4Addr}, nil },
	}

   
	want := tstIP
	rcvd, _ := getIPV4Addr(myMockNetEnum)
	assert.Equal(t, want, rcvd)
	
}
func TestGetBoradcastAddr(t *testing.T) {

	//create the mock Interfaces list
	parsedMac, _ := net.ParseMAC("DE:AD:BE:EF:FF:FF")
	myMockInterfaces := []net.Interface{
		{
			Index:        0,
			MTU:          5,
			Name:         "Ethernet",
			HardwareAddr: parsedMac,
			Flags:        net.FlagUp,
		},
	}

	//create the mock Interface addresses
	myMockIPV4Addr := mockIPV4Addr{}
	myMockIPV6Addr := mockIPV6Addr{}

	//now create a network enumerator
	myMockNetEnum := NetworkEnumerator{
		Interfaces: func() ([]net.Interface, error) { return myMockInterfaces, nil },
		Addrs:      func(*net.Interface) ([]net.Addr, error) { return []net.Addr{myMockIPV6Addr, myMockIPV4Addr}, nil },
	}
   
	want := tstBroadcast
	rcvd, _ := getBroadcastAddr(myMockNetEnum)
	assert.Equal(t, want, rcvd)
	
}

func TestCreateReplyPacket (t *testing.T) {
	tstassignip  := "10.20.30.131"
	giaddr := "0.0.0.0"
	chaddr := "54:b2:03:89:d3:b9"

	//create the mock Interfaces list
	parsedMac, _ := net.ParseMAC("DE:AD:BE:EF:FF:FF")
	myMockInterfaces := []net.Interface{
		{
			Index:        0,
			MTU:          5,
			Name:         "Ethernet",
			HardwareAddr: parsedMac,
			Flags:        net.FlagUp,
		},
	}

	//create the mock Interface addresses
	myMockIPV4Addr := mockIPV4Addr{}
	myMockIPV6Addr := mockIPV6Addr{}

	//now create a network enumerator
	myMockNetEnum := NetworkEnumerator{
		Interfaces: func() ([]net.Interface, error) { return myMockInterfaces, nil },
		Addrs:      func(*net.Interface) ([]net.Addr, error) { return []net.Addr{myMockIPV6Addr, myMockIPV4Addr}, nil },
	}

	ipv4Address, _ := getIPV4Addr(myMockNetEnum)
	serverIP := net.IP.To4(net.ParseIP(ipv4Address))
	assignedIP := net.ParseIP(tstassignip)
	options, _ := setDHCPOptions()

	p, _ := createReplyPacket(dhcpAck, serverIP, assignedIP, options)

	assert.Equal(t, OpCode(2), p.OpCode()) // 2 - bootrequest
	assert.Equal(t, byte(1), p.HType())    // 1 - ethernet
	assert.Equal(t, byte(6), p.HLen())     // 6 - length of MAC
	assert.Equal(t, byte(0), p.Hops())
	assert.Equal(t, []byte{68, 149, 158, 0}, p.XId()) // arbitrary transaction id of 10392900
	assert.Equal(t, []byte{0, 0}, p.Secs())
	assert.Equal(t, []byte{0, 128}, p.Flags()) // flag value of  32768
	assert.Equal(t, "0.0.0.0", p.CIAddr().String())
	assert.Equal(t, tstassignip, p.YIAddr().String())
	assert.Equal(t, "0.0.0.0", p.SIAddr().String())
	assert.Equal(t, giaddr, p.GIAddr().String())
	assert.Equal(t, chaddr, p.CHAddr().String())
	assert.Equal(t, []byte{99, 130, 83, 99}, p.Cookie())

}
