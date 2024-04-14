
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <netinet/in.h> 
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} rb SEC(".maps");

struct packetDetails
{
    char l2_src_addr[6];
    char l2_dst_addr[6];
    unsigned int l3_src_addr;
    unsigned int l3_dst_addr;
    unsigned int l3_protocol;
    unsigned int l3_length;
    unsigned int l3_ttl;
    unsigned int l3_version;
    char l4_protocol[4];
    unsigned int l4_src_port;
    unsigned int l4_dst_port;
};

SEC("xdp")
int packet_details(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;

    struct packetDetails *packet;

    // Verify that the Ethernet packet contains an IP packet
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Move past the Ethernet header to get the IP header
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Extract TCP or UDP header
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(ip + 1);
        strcpy(packet->l4_protocol, "TCP");
        packet->l4_src_port = tcp->source;
        packet->l4_dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(ip + 1);
        strcpy(packet->l4_protocol, "UDP");
        packet->l4_src_port = udp->source;
        packet->l4_dst_port = udp->dest;
    }


    memcpy(packet->l2_dst_addr, eth->h_dest, 6);
    memcpy(packet->l2_src_addr, eth->h_source,6);
    packet->l3_src_addr = ip->saddr;
    packet->l3_dst_addr = ip->daddr;
    packet->l3_protocol = ip->protocol;
    packet->l3_length = ip->tot_len;
    packet->l3_ttl = ip->ttl;
    packet->l3_version = ip->version;

    // Reserve space in the ring buffer
    packet = bpf_ringbuf_reserve(&rb,sizeof(*packet), 0);
  
    if (!packet) {
        // Ideally, we'd handle not being able to
        // reserve space, for testing purposes we'll
        // simply allow it
        return XDP_PASS;
    }

    bpf_ringbuf_submit(packet, 0);

    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";