package pktdump

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPacketICMPv6(t *testing.T) {
	reqPkt := gopacket.NewPacket([]byte{0x60, 0x02, 0x5b, 0xd9, 0x00, 0x10, 0x3a, 0xff, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x4a, 0x26, 0xb2, 0x81, 0x00, 0x00, 0x5b, 0xe8, 0x90, 0x95, 0x00, 0x02, 0x1b, 0x3c}, layers.LayerTypeIPv6, gopacket.Default)
	repPkt := gopacket.NewPacket([]byte{0x64, 0x80, 0x00, 0x00, 0x00, 0x10, 0x3a, 0x2b, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x81, 0x00, 0x49, 0x26, 0xb2, 0x81, 0x00, 0x00, 0x5b, 0xe8, 0x90, 0x95, 0x00, 0x02, 0x1b, 0x3c}, layers.LayerTypeIPv6, gopacket.Default)
	tables := []struct {
		packet   *gopacket.Packet
		icmp     *layers.ICMPv6
		src      string
		dst      string
		length   int
		expected string
	}{
		{nil, &layers.ICMPv6{}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, length 1234"},
		{&reqPkt, &layers.ICMPv6{TypeCode: layers.ICMPv6TypeEchoRequest << 8}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, echo request, id 45697, seq 0, length 1234"},
		{&repPkt, &layers.ICMPv6{TypeCode: layers.ICMPv6TypeEchoReply << 8}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP6, echo reply, id 45697, seq 0, length 1234"},
	}

	for _, table := range tables {
		got := NewFormatter(&Options{}).formatPacketICMPv6(table.packet, table.icmp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketICMPv6 was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketICMPv4(t *testing.T) {
	tables := []struct {
		icmp     *layers.ICMPv4
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.ICMPv4{}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{Id: 999, Seq: 10}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 999, seq 10, length 1234"},
		{&layers.ICMPv4{TypeCode: 0x0800}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo request, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{TypeCode: 0xff00}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP, length 1234"},
	}

	for _, table := range tables {
		got := NewFormatter(&Options{}).formatPacketICMPv4(table.icmp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketICMPv4 was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketTCP(t *testing.T) {
	tables := []struct {
		tcp      *layers.TCP
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.TCP{}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{Seq: 999, Window: 95}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 999:2233, win 95, length 1234"},
		{&layers.TCP{DataOffset: 4}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0:1218, win 0, length 1218"},
		{&layers.TCP{SYN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{SYN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{PSH: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [P.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{FIN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F], seq 0:1234, win 0, length 1234"},
		{&layers.TCP{FIN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F.], seq 0:1234, ack 0, win 0, length 1234"},
		{&layers.TCP{FIN: true, SYN: true, RST: true, PSH: true, ACK: true, URG: true, ECE: true, CWR: true, NS: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [FSRP.UEWN], seq 0:1234, ack 0, win 0, urg 0, length 1234"},
		{&layers.TCP{SYN: true, Options: []layers.TCPOption{{OptionType: 123, OptionLength: 4, OptionData: []byte{0x12, 0x34}}}}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S], seq 0:1234, win 0, options [unknown-123 0x1234], length 1234"},
	}

	for _, table := range tables {
		got := NewFormatter(&Options{}).formatPacketTCP(nil, table.tcp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketTCP was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestFormatSackRelative(t *testing.T) {
	f := NewFormatter(&Options{})
	serverBase := uint32(4071596914)
	serverTCP := &layers.TCP{
		SrcPort: 10000,
		DstPort: 35512,
		Seq:     serverBase,
		ACK:     true,
	}
	f.formatPacketTCP(nil, serverTCP, "srv", "cli", 1024)

	sackData := make([]byte, 8)
	binary.BigEndian.PutUint32(sackData[:4], serverBase+2055997)
	binary.BigEndian.PutUint32(sackData[4:], serverBase+2121452)
	ackTCP := &layers.TCP{
		SrcPort: 35512,
		DstPort: 10000,
		Ack:     serverBase + 1024,
		ACK:     true,
		Options: []layers.TCPOption{{
			OptionType: layers.TCPOptionKindSACK,
			OptionData: sackData,
		}},
	}
	line := f.formatPacketTCP(nil, ackTCP, "cli", "srv", 0)
	if !strings.Contains(line, "sack 1 {2055997:2121452}") {
		t.Fatalf("expected SACK block to be relative, got: %q", line)
	}
}

func TestPacketUDP(t *testing.T) {
	pkt := gopacket.NewPacket([]byte{0x45, 0x00, 0x00, 0x42, 0x9a, 0x66, 0x00, 0x00, 0x40, 0x11, 0xce, 0xc0, 0xc0, 0xa8, 0x48, 0x32, 0xc0, 0xa8, 0x48, 0x01, 0xfb, 0x6a, 0x00, 0x35, 0x00, 0x2e, 0x02, 0xeb, 0x29, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x73, 0x69, 0x67, 0x69, 0x6e, 0x74, 0x02, 0x63, 0x68, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, layers.LayerTypeIPv4, gopacket.Default)
	tables := []struct {
		packet   *gopacket.Packet
		udp      *layers.UDP
		src      string
		dst      string
		expected string
	}{
		{nil, &layers.UDP{Length: 1234}, "test-src", "test-dst", "test-src.0 > test-dst.0: UDP, length 1226"},
		{nil, &layers.UDP{Length: 1234, SrcPort: 68, DstPort: 67}, "test-src", "test-dst", "test-src.68 > test-dst.67: UDP, length 1226"},
		{&pkt, &layers.UDP{Length: 46, SrcPort: 61187, DstPort: 53}, "test-src", "test-dst", "test-src.61187 > test-dst.53: 10628+ [1au] A CH? sigint.ch. (38)"},
	}

	for _, table := range tables {
		got := NewFormatter(&Options{}).formatPacketUDP(table.packet, table.udp, table.src, table.dst)
		if got != table.expected {
			t.Errorf("formatPacketUDP was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestPacketDNS(t *testing.T) {
	tables := []struct {
		dns      *layers.DNS
		src      string
		dst      string
		srcPort  int
		dstPort  int
		length   int
		expected string
	}{
		{&layers.DNS{}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 [0q] (1234)"},
		{&layers.DNS{QDCount: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 (1234)"},
		{&layers.DNS{ID: 999, RD: true, ANCount: 2, NSCount: 10, ARCount: 5, Z: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+% [2a] [0q] [10n] [5au] (1234)"},
		{&layers.DNS{ID: 999, RD: true, QDCount: 1, ANCount: 2, NSCount: 10, ARCount: 5, Z: 2}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2a] [10n] [5au] (1234)"},
		{&layers.DNS{ID: 999, RD: true, QDCount: 2, ANCount: 2, NSCount: 10, ARCount: 5, Z: 3}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+% [2a] [2q] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, ANCount: 2, NSCount: 10, ARCount: 5, Z: 4}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2a] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 1, ANCount: 2, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [1q] [2a] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 2, ANCount: 1, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [2q] [10n] [5au] (1234)"},
		{&layers.DNS{OpCode: 1, ID: 999, RD: true, QDCount: 1, ANCount: 0, NSCount: 10, ARCount: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 999+ [1q] [0a] [10n] [5au] (1234)"},

		{&layers.DNS{QR: true}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, AA: true, TC: true, Z: 2, QDCount: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0*-|$ 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 1, ResponseCode: 1}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 inv_q FormErr- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 2, ResponseCode: 2}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 stat ServFail- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 3, ResponseCode: 3}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op3 NXDomain- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 4, ResponseCode: 4}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 notify NotImp- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 5, ResponseCode: 5}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 update Refused- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 6, ResponseCode: 6}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op6 YXDomain- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 7, ResponseCode: 7}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op7 YXRRSet- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 8, ResponseCode: 8}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 op8 NXRRSet- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 9, ResponseCode: 9}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateA NotAuth- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 10, ResponseCode: 10}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateD NotZone- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 11, ResponseCode: 11}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateDA Resp11- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 12, ResponseCode: 12}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateM Resp12- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 13, ResponseCode: 13}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 updateMA Resp13- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 14, ResponseCode: 14}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 zoneInit Resp14- [0q] 0/0/0 (1234)"},
		{&layers.DNS{QR: true, OpCode: 15, ResponseCode: 15}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0 zoneRef NoChange- [0q] 0/0/0 (1234)"},

		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 3}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 CH Unknown (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeNS, NS: []byte("nsteststring")}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 NS nsteststring. (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeMX, MX: layers.DNSMX{Name: []byte("mxteststring")}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 MX mxteststring. 0 (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Type: layers.DNSTypeSRV, SRV: layers.DNSSRV{Name: []byte("srvteststring"), Port: 999, Priority: 2, Weight: 5}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 Unknown SRV srvteststring.:999 2 5 (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeSOA}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 SOA (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeTXT, TXTs: [][]byte{[]byte("foo"), []byte("bar")}}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 TXT \"foo\" \"bar\" (1234)"},
		{&layers.DNS{QR: true, ANCount: 5, Answers: []layers.DNSResourceRecord{{Class: 1, Type: layers.DNSTypeHINFO}}}, "test-src", "test-dst", 10, 20, 1234, "test-src.10 > test-dst.20: 0- [0q] 5/0/0 HINFO (1234)"},
	}

	for _, table := range tables {
		got := NewFormatter(&Options{}).formatPacketDNS(table.dns, table.src, table.dst, table.srcPort, table.dstPort, table.length)
		if got != table.expected {
			t.Errorf("formatPacketDNS was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestFormat(t *testing.T) {
	tables := []struct {
		payload  []byte
		isIPv6   bool
		expected string
	}{
		{[]byte{0x45, 0x00, 0x00, 0x42, 0x9a, 0x66, 0x00, 0x00, 0x40, 0x11, 0xce, 0xc0, 0xc0, 0xa8, 0x48, 0x32, 0xc0, 0xa8, 0x48, 0x01, 0xfb, 0x6a, 0x00, 0x35, 0x00, 0x2e, 0x02, 0xeb, 0x29, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x73, 0x69, 0x67, 0x69, 0x6e, 0x74, 0x02, 0x63, 0x68, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false, "IP 192.168.72.50.64362 > 192.168.72.1.53: 10628+ [1au] A CH? sigint.ch. (38)"},
		{[]byte{0x45, 0x10, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xdc, 0xc5, 0xc0, 0xa8, 0x48, 0x32, 0xac, 0xd9, 0xa8, 0x2e, 0xe4, 0xd0, 0x00, 0x50, 0x20, 0x0d, 0x0d, 0x7a, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x5c, 0xd8, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x32, 0xc6, 0x36, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}, false, "IP 192.168.72.50.58576 > 172.217.168.46.80: Flags [S], seq 537726330, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 851850963 ecr 0,sackOK,eol], length 0"},
		{[]byte{0x60, 0x0a, 0x8c, 0x43, 0x00, 0x2c, 0x06, 0xff, 0x2a, 0x01, 0x02, 0xa8, 0x85, 0x02, 0x1f, 0x01, 0x45, 0x38, 0x31, 0x33, 0x04, 0x0f, 0x0a, 0x2a, 0x2a, 0x00, 0x14, 0x50, 0x40, 0x0a, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e, 0xe4, 0xd1, 0x00, 0x50, 0x96, 0x3e, 0x44, 0x97, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0xec, 0x6e, 0x00, 0x00, 0x02, 0x04, 0x05, 0x98, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x32, 0xc8, 0x5c, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00}, true, "IP6 2a01:2a8:8502:1f01:4538:3133:40f:a2a.58577 > 2a00:1450:400a:802::200e.80: Flags [S], seq 2520663191, win 65535, options [mss 1432,nop,wscale 6,nop,nop,TS val 851991598 ecr 0,sackOK,eol], length 0"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0xc9, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0xdf, 0x70, 0xff, 0xfe, 0x6c, 0xa9, 0xd7, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x85, 0x80, 0x3a, 0x57, 0xab, 0x95, 0x6f, 0x00, 0x35, 0xf2, 0x84, 0x00, 0xc9, 0x40, 0x35, 0x58, 0xc2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0xf7, 0x00, 0x1b, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x11, 0x6f, 0x00, 0x2f, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65, 0x64, 0x69, 0x72, 0x06, 0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0xc0, 0x41, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x09, 0x7d, 0x00, 0x19, 0x05, 0x65, 0x36, 0x38, 0x35, 0x38, 0x05, 0x64, 0x73, 0x63, 0x65, 0x39, 0x0a, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x41, 0xc0, 0x8d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x02, 0x14, 0xd6, 0xf3, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, true, "IP6 fe80::eadf:70ff:fe6c:a9d7.53 > fe80::885:803a:57ab:956f.62084: 22722 4/0/1 CNAME www.apple.com.edgekey.net., CNAME www.apple.com.edgekey.net.globalredir.akadns.net., CNAME e6858.dsce9.akamaiedge.net., A 2.20.214.243 (193)"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0xc9, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0xdf, 0x70, 0xff, 0xfe, 0x6c, 0xa9, 0xd7, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x85, 0x80, 0x3a, 0x57, 0xab, 0x95, 0x6f, 0x00, 0x35, 0xf2, 0x84, 0x00, 0xc9, 0x40, 0x35, 0x58, 0xc2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0xf7, 0x00, 0x1b, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x11, 0x6f, 0x00, 0x2f, 0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07, 0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x0b, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x72, 0x65, 0x64, 0x69, 0x72, 0x06, 0x61, 0x6b, 0x61, 0x64, 0x6e, 0x73, 0xc0, 0x41, 0xc0, 0x52, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x09, 0x7d, 0x00, 0x19, 0x05, 0x65, 0x36, 0x38, 0x35, 0x38, 0x05, 0x64, 0x73, 0x63, 0x65, 0x39, 0x0a, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0, 0x41, 0xc0, 0x8d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x02, 0x14, 0xd6, 0xf3, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, true, "IP6 fe80::eadf:70ff:fe6c:a9d7.53 > fe80::885:803a:57ab:956f.62084: 22722 4/0/1 CNAME www.apple.com.edgekey.net., CNAME www.apple.com.edgekey.net.globalredir.akadns.net., CNAME e6858.dsce9.akamaiedge.net., A 2.20.214.243 (193)"},
		{[]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xb3, 0xf9, 0xdc, 0xd0, 0x6a, 0x53, 0xc5, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x3a, 0x00, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x8f, 0x00, 0x49, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb}, true, "IP6 fe80::10b3:f9dc:d06a:53c5 > ff02::16: ICMP6, length 36"},
		{[]byte{0x6c, 0x05, 0x41, 0x6d, 0x00, 0x28, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0a, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x28, 0x0a, 0x0a, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xae, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x01, 0x00, 0x00, 0x13, 0x00, 0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0b}, true, "IP6 fe80::a0a:a0a > ff02::5: OSPFv3, Hello, length 40"},
		{[]byte{0x45, 0x00, 0x00, 0x54, 0xee, 0x0a, 0x00, 0x00, 0x40, 0x01, 0x82, 0xc3, 0xc0, 0xa8, 0x48, 0x32, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x5e, 0x47, 0xc3, 0x28, 0x00, 0x00, 0x5b, 0xe8, 0x50, 0xec, 0x00, 0x07, 0x3e, 0xb1, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}, false, "IP 192.168.72.50 > 1.0.0.1: ICMP echo request, id 49960, seq 0, length 64"},
		{[]byte{0x46, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x01, 0x02, 0xfb, 0xed, 0xc0, 0xa8, 0x48, 0x23, 0xe0, 0x00, 0x00, 0x16, 0x94, 0x04, 0x00, 0x00, 0x22, 0x00, 0xf9, 0x02, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0xfb}, false, "IP 192.168.72.35 > 224.0.0.22: IGMP, length 16"},
	}

	for _, table := range tables {
		var packet gopacket.Packet
		if table.isIPv6 {
			packet = gopacket.NewPacket(table.payload, layers.LayerTypeIPv6, gopacket.Default)
		} else {
			packet = gopacket.NewPacket(table.payload, layers.LayerTypeIPv4, gopacket.Default)
		}
		got := Format(packet)
		if got != table.expected {
			t.Errorf("Format was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func Test_ip_options(t *testing.T) {
	packet := gopacket.NewPacket([]byte{
		//0, 80, 86, 235, 188, 78, 0, 12, 41, 142, 49, 243, 8, 0,
		79, 0, 0, 80, 29, 38, 0, 0, 64, 6, 48, 70, 10, 0, 2, 15, 1, 1, 1,
		1, 7, 39, 8, 1, 2, 3, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 194, 0, 80, 111,
		152, 56, 207, 17, 225, 164, 243, 80, 2, 2, 0, 56, 132, 0, 0}, layers.LayerTypeIPv4, gopacket.Default)

	got := FormatWithStyle(packet, FormatStyleVerbose)
	t.Log(got)
	if !strings.Contains(got, "options (RR 1.2.3.4, 1.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0,EOL))") {
		t.Errorf("IP options were not formatted correctly, got: '%s'.", got)
	}
}

func TestTCPRelativeSequenceProgression(t *testing.T) {
	formatter := NewFormatter(&Options{})

	const (
		headerLen = 20
		clientIP  = "10.0.0.1"
		serverIP  = "10.0.0.2"
	)

	clientPort := layers.TCPPort(12345)
	serverPort := layers.TCPPort(80)

	clientSYN := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 1000, SYN: true, DataOffset: 5}
	got := formatter.formatPacketTCP(nil, clientSYN, clientIP, serverIP, headerLen)
	if !strings.Contains(got, "seq 1000") {
		t.Fatalf("expected absolute seq on first SYN, got %q", got)
	}
	if strings.Contains(got, "ack ") {
		t.Fatalf("unexpected ack on initial SYN, got %q", got)
	}

	synAck := &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 5000, Ack: 1001, SYN: true, ACK: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, synAck, serverIP, clientIP, headerLen)
	if !strings.Contains(got, "seq 5000") || !strings.Contains(got, "ack 1001") {
		t.Fatalf("expected absolute seq/ack on SYN|ACK, got %q", got)
	}

	dupSynAck := &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 5000, Ack: 1001, SYN: true, ACK: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, dupSynAck, serverIP, clientIP, headerLen)
	if !strings.Contains(got, "seq 5000") {
		t.Fatalf("duplicate SYN|ACK should stay absolute, got %q", got)
	}

	finalAck := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 1001, Ack: 5001, ACK: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, finalAck, clientIP, serverIP, headerLen)
	if strings.Contains(got, "seq ") {
		t.Fatalf("pure ACK should omit seq, got %q", got)
	}
	if !strings.Contains(got, "ack 1") {
		t.Fatalf("expected relative ACK of 1 after handshake, got %q", got)
	}

	clientDataLen := headerLen + 100
	clientData := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 1001, Ack: 5001, ACK: true, PSH: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, clientData, clientIP, serverIP, clientDataLen)
	if !strings.Contains(got, "seq 1:101") || !strings.Contains(got, "ack 1") {
		t.Fatalf("expected relative seq/ack for client data, got %q", got)
	}

	serverDataLen := headerLen + 150
	serverData := &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 5001, Ack: 1101, ACK: true, PSH: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, serverData, serverIP, clientIP, serverDataLen)
	if !strings.Contains(got, "seq 1:151") || !strings.Contains(got, "ack 101") {
		t.Fatalf("expected relative seq/ack for server data, got %q", got)
	}
}

func TestTCPRelativeResets(t *testing.T) {
	formatter := NewFormatter(&Options{})

	const (
		headerLen = 20
		clientIP  = "10.0.0.1"
		serverIP  = "10.0.0.2"
	)

	clientPort := layers.TCPPort(2000)
	serverPort := layers.TCPPort(80)

	formatter.formatPacketTCP(nil, &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 3000, SYN: true, DataOffset: 5}, clientIP, serverIP, headerLen)
	formatter.formatPacketTCP(nil, &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 8000, Ack: 3001, SYN: true, ACK: true, DataOffset: 5}, serverIP, clientIP, headerLen)

	rst := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 3100, RST: true, DataOffset: 5}
	formatter.formatPacketTCP(nil, rst, clientIP, serverIP, headerLen)

	postRST := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 9000, PSH: true, DataOffset: 5}
	got := formatter.formatPacketTCP(nil, postRST, clientIP, serverIP, headerLen+40)
	if !strings.Contains(got, "seq 9000:9040") {
		t.Fatalf("expected absolute seq after RST reset, got %q", got)
	}

	serverPost := &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 12000, PSH: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, serverPost, serverIP, clientIP, headerLen+20)
	if !strings.Contains(got, "seq 12000:12020") {
		t.Fatalf("expected absolute seq for server after RST, got %q", got)
	}

	newSyn := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 4000, SYN: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, newSyn, clientIP, serverIP, headerLen)
	if !strings.Contains(got, "seq 4000") {
		t.Fatalf("expected fresh baseline after SYN reset, got %q", got)
	}
	if strings.Contains(got, "ack ") {
		t.Fatalf("initial SYN should not include ack, got %q", got)
	}

	newSynAck := &layers.TCP{SrcPort: serverPort, DstPort: clientPort, Seq: 9000, Ack: 4001, SYN: true, ACK: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, newSynAck, serverIP, clientIP, headerLen)
	if !strings.Contains(got, "seq 9000") || !strings.Contains(got, "ack 4001") {
		t.Fatalf("expected absolute server SYN|ACK after restart, got %q", got)
	}

	newAck := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 4001, Ack: 9001, ACK: true, DataOffset: 5}
	got = formatter.formatPacketTCP(nil, newAck, clientIP, serverIP, headerLen)
	if strings.Contains(got, "seq ") {
		t.Fatalf("pure ACK after handshake should omit seq, got %q", got)
	}
	if !strings.Contains(got, "ack 1") {
		t.Fatalf("expected relative ack reset to 1 after new handshake, got %q", got)
	}
}

func TestTCPRelativeMidstream(t *testing.T) {
	formatter := NewFormatter(&Options{})

	const (
		headerLen = 20
		clientIP  = "10.0.0.1"
		serverIP  = "10.0.0.2"
	)

	clientPort := layers.TCPPort(3000)
	serverPort := layers.TCPPort(80)

	pkt1 := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 9000, Ack: 4000, ACK: true, PSH: true, DataOffset: 5}
	got1 := formatter.formatPacketTCP(nil, pkt1, clientIP, serverIP, headerLen+50)
	if !strings.Contains(got1, "seq 9000:9050") || !strings.Contains(got1, "ack 4000") {
		t.Fatalf("expected absolute values on first mid-stream packet, got %q", got1)
	}

	pkt2 := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: 9050, Ack: 4000, ACK: true, PSH: true, DataOffset: 5}
	got2 := formatter.formatPacketTCP(nil, pkt2, clientIP, serverIP, headerLen+30)
	if !strings.Contains(got2, "seq 50:80") || !strings.Contains(got2, "ack 4000") {
		t.Fatalf("expected relative sequence but absolute ack without peer baseline, got %q", got2)
	}
}

func TestTCPRelativeOptionDisabled(t *testing.T) {
	opts := &Options{}
	opts.SetRelativeTCPSeq(false)
	formatter := NewFormatter(opts)

	const (
		headerLen = 20
		srcIP     = "10.1.1.1"
		dstIP     = "10.1.1.2"
	)

	tcp1 := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1500, Ack: 2000, ACK: true, PSH: true, DataOffset: 5}
	out1 := formatter.formatPacketTCP(nil, tcp1, srcIP, dstIP, headerLen+40)
	if !strings.Contains(out1, "seq 1500:1540") || !strings.Contains(out1, "ack 2000") {
		t.Fatalf("expected absolute formatting when relative disabled, got %q", out1)
	}

	tcp2 := &layers.TCP{SrcPort: 1234, DstPort: 80, Seq: 1540, Ack: 2000, ACK: true, PSH: true, DataOffset: 5}
	out2 := formatter.formatPacketTCP(nil, tcp2, srcIP, dstIP, headerLen+20)
	if !strings.Contains(out2, "seq 1540:1560") || !strings.Contains(out2, "ack 2000") {
		t.Fatalf("expected subsequent packets to remain absolute when disabled, got %q", out2)
	}
}

func TestFormatConcurrency(t *testing.T) {
	raw := []byte{0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x13, 0x88, 0x50, 0x10, 0x40, 0x00, 0x72, 0x10, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4}
	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Format(packet)
		}()
	}
	wg.Wait()
}

func TestTCPDumpSequenceParity(t *testing.T) {
	formatter := NewFormatter(&Options{})
	demoPath := filepath.Join("cmd", "pcapdump", "demo.pcap")
	refPath := filepath.Join("cmd", "pcapdump", "tcpdump.txt")

	expectedLines, err := readLines(refPath)
	if err != nil {
		t.Fatalf("failed to load tcpdump reference: %v", err)
	}
	trimmed := expectedLines[:0]
	for _, line := range expectedLines {
		line = strings.TrimSpace(line)
		if line != "" {
			trimmed = append(trimmed, line)
		}
	}
	expectedLines = trimmed

	f, err := os.Open(demoPath)
	if err != nil {
		t.Fatalf("failed to open demo pcap: %v", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create pcap reader: %v", err)
	}
	src := gopacket.NewPacketSource(reader, reader.LinkType())

	idx := 0
	for packet := range src.Packets() {
		if idx >= len(expectedLines) {
			t.Fatalf("pcap produced more packets (%d) than tcpdump reference (%d)", idx+1, len(expectedLines))
		}

		expectedFields, err := extractSeqAck(expectedLines[idx])
		if err != nil {
			t.Fatalf("failed to parse tcpdump line %d: %v", idx+1, err)
		}
		gotLine := formatter.Format(packet)
		gotFields, err := extractSeqAck(gotLine)
		if err != nil {
			t.Fatalf("failed to parse formatter line %d: %v", idx+1, err)
		}

		if expectedFields.hasSeq != gotFields.hasSeq {
			t.Fatalf("line %d: seq presence mismatch (expected %v, got %v)\nexpected: %s\n     got: %s", idx+1, expectedFields.hasSeq, gotFields.hasSeq, expectedLines[idx], gotLine)
		}
		if expectedFields.hasSeq {
			if expectedFields.seqStart != gotFields.seqStart {
				t.Fatalf("line %d: seq start mismatch (expected %d, got %d)\nexpected: %s\n     got: %s", idx+1, expectedFields.seqStart, gotFields.seqStart, expectedLines[idx], gotLine)
			}
			if expectedFields.hasSeqEnd != gotFields.hasSeqEnd {
				t.Fatalf("line %d: seq end presence mismatch\nexpected: %s\n     got: %s", idx+1, expectedLines[idx], gotLine)
			}
			if expectedFields.hasSeqEnd && expectedFields.seqEnd != gotFields.seqEnd {
				t.Fatalf("line %d: seq end mismatch (expected %d, got %d)\nexpected: %s\n     got: %s", idx+1, expectedFields.seqEnd, gotFields.seqEnd, expectedLines[idx], gotLine)
			}
		}

		if expectedFields.hasAck != gotFields.hasAck {
			t.Fatalf("line %d: ack presence mismatch (expected %v, got %v)\nexpected: %s\n     got: %s", idx+1, expectedFields.hasAck, gotFields.hasAck, expectedLines[idx], gotLine)
		}
		if expectedFields.hasAck && expectedFields.ack != gotFields.ack {
			t.Fatalf("line %d: ack mismatch (expected %d, got %d)\nexpected: %s\n     got: %s", idx+1, expectedFields.ack, gotFields.ack, expectedLines[idx], gotLine)
		}

		idx++
	}

	if idx != len(expectedLines) {
		t.Fatalf("tcpdump reference contains %d packets but pcap produced %d", len(expectedLines), idx)
	}
}

type seqAckFields struct {
	hasSeq    bool
	seqStart  uint64
	hasSeqEnd bool
	seqEnd    uint64
	hasAck    bool
	ack       uint64
}

func extractSeqAck(line string) (seqAckFields, error) {
	fields := seqAckFields{}

	if idx := strings.Index(line, ", seq "); idx >= 0 {
		segment := takeUntilComma(line[idx+len(", seq "):])
		start, end, hasEnd, err := parseSeqToken(segment)
		if err != nil {
			return seqAckFields{}, fmt.Errorf("parse seq %q: %w", segment, err)
		}
		fields.hasSeq = true
		fields.seqStart = start
		fields.hasSeqEnd = hasEnd
		fields.seqEnd = end
	}

	if idx := strings.Index(line, ", ack "); idx >= 0 {
		segment := takeUntilComma(line[idx+len(", ack "):])
		segment = strings.TrimSpace(segment)
		if segment != "" {
			value, err := strconv.ParseUint(segment, 10, 64)
			if err != nil {
				return seqAckFields{}, fmt.Errorf("parse ack %q: %w", segment, err)
			}
			fields.hasAck = true
			fields.ack = value
		}
	}

	return fields, nil
}

func parseSeqToken(token string) (start uint64, end uint64, hasEnd bool, err error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, 0, false, fmt.Errorf("empty seq token")
	}
	parts := strings.Split(token, ":")
	start, err = strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return 0, 0, false, err
	}
	if len(parts) > 1 {
		endStr := strings.TrimSpace(parts[1])
		if endStr != "" {
			end, err = strconv.ParseUint(endStr, 10, 64)
			if err != nil {
				return 0, 0, false, err
			}
			hasEnd = true
		}
	}
	return start, end, hasEnd, nil
}

func takeUntilComma(s string) string {
	if idx := strings.IndexRune(s, ','); idx >= 0 {
		return s[:idx]
	}
	return s
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
