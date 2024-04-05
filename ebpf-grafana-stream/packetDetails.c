
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <string.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} rb SEC(".maps");

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

SEC("xdp")
int packet_details(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip;

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

    // Reserve space in the ring buffer
    packet = bpf_ringbuf_reserve(&rb,sizeof(*packet), 0);
  
    if (!packet) {
        // Ideally, we'd handle not being able to
        // reserve space, for testing purposes we'll
        // simply allow it
        return XDP_PASS;
    }

    memcpy(packet->l2_dst_addr, eth->h_dest, 6);
    memcpy(packet->l2_src_addr, eth->h_source,6);
    packet->l3_src_addr = ip->saddr;
    packet->l3_dst_addr = ip->daddr;
    packet->l3_protocol = ip->protocol;
    packet->l3_length = ip->tot_len;
    packet->l3_ttl = ip->ttl;
    packet->l3_version = ip->version;

    bpf_ringbuf_submit(packet, 0);

    return XDP_PASS;

}


char LICENSE[] SEC("license") = "GPL";