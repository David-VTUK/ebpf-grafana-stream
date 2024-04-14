package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/david-vtuk/ebpf-grafana-stream/pkg/netprotocols"
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
	L4_src_port uint16
	L4_dst_port uint16
	L4_protocol [4]byte
}

func main() {

	// Read environment variables
	grafanaURL := os.Getenv("GRAFANA_URL")
	grafanaToken := os.Getenv("GRAFANA_TOKEN")
	networkInterface := os.Getenv("INTERFACE")

	if grafanaURL == "" || grafanaToken == "" || networkInterface == "" {
		fmt.Println("URL", grafanaURL, "Token", grafanaToken, "Interface", networkInterface)
		log.Fatal("Environment variables not set. Please set GRAFANA_URL, GRAFANA_TOKEN and INTERFACE")
	}

	var objs packetDetailsObjects
	if err := loadPacketDetailsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ring, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("Unable to open ring buffer: %s", err)
	}
	defer ring.Close()

	iface, err := net.InterfaceByName(networkInterface)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", networkInterface, err)
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

			sendToGrafana(packet, grafanaURL, grafanaToken)

		}

	}
}

func sendToGrafana(packet packetDetails, grafanaURL string, grafanaToken string) error {

	//Convert MAC address from Decimal to HEX
	sourceMacAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", packet.L2_src_addr[0], packet.L2_src_addr[1], packet.L2_src_addr[2], packet.L2_src_addr[3], packet.L2_src_addr[4], packet.L2_src_addr[5])
	destinationMacAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", packet.L2_dst_addr[0], packet.L2_dst_addr[1], packet.L2_dst_addr[2], packet.L2_dst_addr[3], packet.L2_dst_addr[4], packet.L2_dst_addr[5]) //"packet_details source_mac=\"%s\"

	//Convert IP address from Decimal to IPv4
	sourceIP := net.IPv4(byte(packet.L3_src_addr), byte(packet.L3_src_addr>>8), byte(packet.L3_src_addr>>16), byte(packet.L3_src_addr>>24)).String()
	destIP := net.IPv4(byte(packet.L3_dst_addr), byte(packet.L3_dst_addr>>8), byte(packet.L3_dst_addr>>16), byte(packet.L3_dst_addr>>24)).String()

	//Convert Protocol number to name
	protocolName := netprotocols.Translate(int(packet.L3_protocol))

	//Create Telegraph message
	telegrafMessage := fmt.Sprintf("packet_details source_mac=\"%s\",destination_mac=\"%s\",source_ip=\"%s\",destination_ip=\"%s\",protocol=\"%s\",length=%di,ttl=%di,version=%di, source_port=%di, destination_port=%di, protocol=\"%s\"\n",
		sourceMacAddress, destinationMacAddress, sourceIP, destIP, protocolName, packet.L3_length, packet.L3_ttl, packet.L3_version, packet.L4_src_port, packet.L4_dst_port, packet.L4_protocol)

	//http post to grafana
	req, err := http.NewRequest("POST", grafanaURL, strings.NewReader(telegrafMessage))
	if err != nil {
		log.Printf("Failed to create HTTP request: %v", err)
		return err
	}

	//fmt.Println(packet.L3_ttl)

	if packet.L3_ttl == 1 {
		fmt.Println(telegrafMessage)
	}

	// Add bearer token to the request header
	req.Header.Set("Authorization", "Bearer "+grafanaToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to send HTTP request: %v", err)
		return err
	}
	defer resp.Body.Close()

	return nil
}
