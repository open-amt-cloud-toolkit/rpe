/**************************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 *
 * Many functions in this file take inspiration from the dhcp4 package:
 *   https://pkg.go.dev/github.com/krolaw/dhcp4
 * written by:
 *   http://richard.warburton.it/
 * under the following copyright and permissions:
 *   Copyright (c) 2014 Skagerrak Software Limited. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are
 *   met:
 *
 *      * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *      * Neither the name of Skagerrak Software Limited nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/
package rpe

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"
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

var validWiredInterfaces = map[string] bool {
	"Ethernet": true,   // Windows
	"eth0": 	true,	// Linux legacy
	"eno1":		true,	// Linux
}

var domain string
var assignIp string = "169.254.214.131"
var clientMac string = "54-B2-03-89-D3-B9"
var subnetMask net.IP = []byte{255, 255, 255, 0}
var dns net.IP = []byte{8, 8, 8, 8}
var padder [272]byte

const (
	destPort string = "68" // DHCP packets written to port 68

	dhcpDiscover MessageType = 1
	dhcpOffer    MessageType = 2
	dhcpRequest  MessageType = 3
	dhcpDecline  MessageType = 4
	dhcpAck      MessageType = 5
	dhcpNack     MessageType = 6
	dhcpRelease  MessageType = 7
	dhcpInform   MessageType = 8

	bootRequest OpCode = 1
	bootReply   OpCode = 2

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

func SendAck(domainName string) error {

	domain = domainName

	// DHCP packets are broadcasted.  Get broadcast address
	broadcast, error := getBroadcastAddr(NetPkgEnumerator())

	if error != nil {
		return error
	}
	// Create a UDP connection
	udp := UDPConnection{}
	error = udp.Connect(broadcast, destPort)
	if error != nil {
		log.Println("failed dial step ", error)
		return error
	}
	defer udp.Close()

	// Initialize info for ack packet
	ipv4Address, error := getIPV4Addr(NetPkgEnumerator())
	if error != nil {
		return error
	}
	serverIP := net.IP.To4(net.ParseIP(ipv4Address))
	assignedIP := net.ParseIP(assignIp)
	options, error := setDHCPOptions()
	if error != nil {
		return error
	}

	// Create ack packet
	packet, error := createReplyPacket(dhcpAck, serverIP, assignedIP, options)
	if error != nil {
		return error
	}

	// Write ack packet
	error = udp.Write(packet)
	if error != nil {
		log.Println(error)
	}

	return error
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

func createReplyPacket(msgType MessageType, serverId net.IP, yIAddr net.IP, opitons []Option) (Packet, error) {
	packet := NewPacket(bootReply)
	transactionID := IntToByteArray(10392900, 4)
	if transactionID != nil {
		packet.SetXId(transactionID)
	} else {
		return packet, errors.New("invalid transaction Id")
	}
	flagsValue := IntToByteArray(32768, 2)
	if flagsValue != nil {
		packet.SetFlags(flagsValue)
	} else {
		return packet, errors.New("invalid flags value")
	}
	packet.SetYIAddr(yIAddr)
	packet.SetGIAddr(net.ParseIP("0.0.0.0"))
	cMac, _ := net.ParseMAC(clientMac)
	packet.SetCHAddr(cMac)
	packet.AddOption(OptionDHCPMessageType, []byte{byte(msgType)})
	packet.AddOption(OptionServerIdentifier, []byte(serverId))
	for _, opt := range opitons {
		packet.AddOption(opt.Code, opt.Value)
	}
	packet.PadToMinSize()
	return packet, nil
}

func setDHCPOptions() ([]Option, error) {
	var opts []Option
	addDHCPOption(&opts, OptionSubnetMask, subnetMask.To4())
	optionTimeOffset := IntToByteArray(0, 4)
	if optionTimeOffset != nil {
		addDHCPOption(&opts, OptionTimeOffset, optionTimeOffset)
	} else {
		return opts, errors.New("invalid Option Time Offset")
	}
	addDHCPOption(&opts, OptionDomainNameServer, dns.To4())
	addDHCPOption(&opts, OptionDomainName, []byte(domain))
	addDHCPOption(&opts, OptionDefaultTTL, []byte{64})
	optionIpLeaseTime := IntToByteArray(86400, 4)
	if optionIpLeaseTime != nil {
		addDHCPOption(&opts, OptionIPLeaseTime, optionIpLeaseTime)
	} else {
		return opts, errors.New("invalid Option IP Lease Time")
	}
	optionRenewalTime := IntToByteArray(43200, 4)
	if optionRenewalTime != nil {
		addDHCPOption(&opts, OptionRenewalTime, optionRenewalTime)
	} else {
		return opts, errors.New("invalid Option Renewal Time")
	}
	optionRebindingTime := IntToByteArray(75600, 4)
	if optionRebindingTime != nil {
		addDHCPOption(&opts, OptionRebindingTime, optionRebindingTime)
	} else {
		return opts, errors.New("invalid Option Rebinding Time")
	}

	return opts, nil
}

func addDHCPOption(array *[]Option, code OptionCode, value []byte) {
	tmp := Option{Code: code, Value: value}
	*array = append(*array, tmp)
}

func getIPV4Addr(ne NetworkEnumerator) (string, error) {
	list, error := ne.Interfaces()
	if error != nil {
		log.Println("Failed getting network interfaces: ", error)
	} else {
		// Find "wired" network interface.  "Ethernet" for Windows, "eth0" or "eno1" for Linux
		for _, iface := range list {
			if validWiredInterfaces[iface.Name] {
				addrs, error := ne.Addrs(&iface)  // get addresses associated with the interface
				if error != nil {
					log.Println("Failed getting interface addresses: ", error)
				} else {
					// Find Ipv4 address (won't contain a :) in list of addresses
					for addrIndex := range addrs {
						if strings.Contains(addrs[addrIndex].String(), ":") {
							continue
						}
						// Strip off CIDR notation (/8, /16, etc.)
						i := strings.Index(addrs[addrIndex].String(), "/")
						return strings.TrimSpace(addrs[addrIndex].String()[:i]), error

					}
					return "", errors.New("no IPV4 address found")
				}
			}
		}
	}
	return "", error
}

func getBroadcastAddr(ne NetworkEnumerator) (string, error) {
	subnet := "0.0.0"

	localIp, error := getIPV4Addr(ne)
	if error == nil {
		subnet = localIp[:strings.LastIndex(localIp, ".")]
	}

	return subnet + ".255", error
}

func (pkt *Packet) PadToMinSize() {
	if n := len(*pkt); n < 272 {
		*pkt = append(*pkt, padder[:272-n]...)
	}
}

func (pkt *Packet) AddOption(optCode OptionCode, value []byte) {
	*pkt = append((*pkt)[:len(*pkt)-1], []byte{byte(optCode), byte(len(value))}...)
	*pkt = append(*pkt, value...)
	*pkt = append(*pkt, byte(End))
}

func NewPacket(opCode OpCode) Packet {
	packet := make(Packet, 241)
	packet.SetOpCode(opCode)
	packet.SetHType(1)                        // Ethernet
	packet.SetCookie([]byte{99, 130, 83, 99}) // DHCP "Magic Cookie"
	packet[240] = byte(End)

	return packet
}

func IntToByteArray(num int, bytes int) []byte {
	byteArray := []byte(nil)
	switch bytes {
	case 2:
		byteArray = make([]byte, bytes)
		binary.LittleEndian.PutUint16(byteArray, uint16(num))
	case 4:
		byteArray = make([]byte, bytes)
		binary.LittleEndian.PutUint32(byteArray, uint32(num))
	default:
		log.Println("IntToByteArray() - Invalid byte count request: ", bytes)
	}
	return byteArray
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
