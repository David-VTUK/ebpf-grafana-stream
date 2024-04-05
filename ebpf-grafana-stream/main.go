package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type packetDetails struct {
	L2_src_addr [6]byte
	L2_dst_addr [6]byte
	L3_src_addr uint32
	L3_dst_addr uint32
	L3_protocol uint32
	L3_length   uint32
	L3_ttl      uint32
	L3_version  uint32
}

func main() {

	var objs packetDetailsObjects
	if err := loadPacketDetailsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ring, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatal("Unable to open ring buffer")
	}
	defer ring.Close()

	ifname := "enp1s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach packetDetails to the network interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PacketDetails,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		default:
			e, err := ring.Read()
			if err != nil {
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			var packet packetDetails
			byteReader := bytes.NewReader(e.RawSample)
			err = binary.Read(byteReader, binary.LittleEndian, &packet)
			if err != nil {
				log.Printf("Unable to marshall to struct: %v", err)
			}

			sourceMacAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", packet.L2_src_addr[0], packet.L2_src_addr[1], packet.L2_src_addr[2], packet.L2_src_addr[3], packet.L2_src_addr[4], packet.L2_src_addr[5])
			destinationMacAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", packet.L2_dst_addr[0], packet.L2_dst_addr[1], packet.L2_dst_addr[2], packet.L2_dst_addr[3], packet.L2_dst_addr[4], packet.L2_dst_addr[5])

			sourceIP := net.IPv4(byte(packet.L3_src_addr), byte(packet.L3_src_addr>>8), byte(packet.L3_src_addr>>16), byte(packet.L3_src_addr>>24)).String()
			destIP := net.IPv4(byte(packet.L3_dst_addr), byte(packet.L3_dst_addr>>8), byte(packet.L3_dst_addr>>16), byte(packet.L3_dst_addr>>24)).String()

			protocolName := protocolNumberToName(packet.L3_protocol)
			l3PacketLength := packet.L3_length

			l3TTL := packet.L3_ttl
			l3Version := packet.L3_version

			fmt.Println(sourceMacAddress, destinationMacAddress, sourceIP, destIP, protocolName, l3PacketLength, l3TTL, l3Version)

		}

	}
}

func protocolNumberToName(protocolNumber uint32) string {
	var protocols = map[int]string{
		1:   "ICMP",
		2:   "IGMP",
		3:   "GGP",
		4:   "IP-in-IP",
		5:   "ST",
		6:   "TCP",
		7:   "CBT",
		8:   "EGP",
		9:   "IGP",
		10:  "BBN-RCC-MON",
		11:  "NVP-II",
		12:  "PUP",
		13:  "ARGUS",
		14:  "EMCON",
		15:  "XNET",
		16:  "CHAOS",
		17:  "UDP",
		18:  "MUX",
		19:  "DCN-MEAS",
		20:  "HMP",
		21:  "PRM",
		22:  "XNS-IDP",
		23:  "TRUNK-1",
		255: "Reserved",
	}

	return protocols[int(protocolNumber)]
}
