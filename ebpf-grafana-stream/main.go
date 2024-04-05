package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

/*
struct packetDetails
{
    unsigned char l2_src_addr[6];
    unsigned char l2_dst_addr[6];
    unsigned int l3_src_addr;
    unsigned int l3_dst_addr;
    unsigned int l3_protocol;
    unsigned int l3_length;
    unsigned int l3_ttl;
    unsigned int l3_version;

};
*/

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

			fmt.Println(packet.L2_src_addr)

			mac, err := decimalToMAC((string(packet.L2_src_addr[:])))
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			fmt.Println(mac)

		}

	}
}

func decimalToMAC(decimalString string) (string, error) {
	// Step 1: Parse the decimal string to an integer
	num, err := strconv.ParseUint(decimalString, 10, 64)
	if err != nil {
		return "", err // Handle the error if the string is not a valid number
	}

	// Step 2: Convert the integer to its byte representation
	macBytes := []byte{
		byte(num >> 40),
		byte(num >> 32 & 0xFF),
		byte(num >> 24 & 0xFF),
		byte(num >> 16 & 0xFF),
		byte(num >> 8 & 0xFF),
		byte(num & 0xFF),
	}

	// Step 3: Format the bytes into a MAC address string
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5])

	return mac, nil
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

	for k, v := range protocols {
		if k == int(protocolNumber) {
			return v
		}
	}

	return "unknown"
}
