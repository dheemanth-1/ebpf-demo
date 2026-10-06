//go:build ignore
 
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
 
// EtherType and Protocol constants
#define ETH_P_IP 0x0800  // IPv4 Protocol
#define IPPROTO_TCP 6    // TCP Protocol
 
// bpf_printk is a GPL-only helper, so the program must declare a GPL-compatible
// license. If your existing file already has this line, keep only one.
char __license[] SEC("license") = "Dual MIT/GPL";
 
// A one-entry array map that holds the port to drop (host byte order).
// Userspace writes to it; this program reads it on every packet.
// Value 0 means "filter disabled": nothing is dropped.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} target_port SEC(".maps");
 
SEC("xdp")
int filter_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
 
    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
 
    // IPv4 header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    if (ip->protocol != IPPROTO_TCP || ip->ihl < 5) {
        return XDP_PASS;
    }
 
    // TCP header (IP header length is ihl * 4 bytes)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }
 
    // Read the currently configured port from the map.
    // The NULL check is mandatory: the verifier rejects the program without it.
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&target_port, &key);
    if (!port || *port == 0) {
        return XDP_PASS;
    }
 
    __u16 dest_port = bpf_ntohs(tcp->dest);
    if (dest_port == *port) {
        __u16 src_port = bpf_ntohs(tcp->source);
        bpf_printk("Dropping packet on Port %d from Src Port %d", dest_port, src_port);
        return XDP_DROP;
    }
 
    return XDP_PASS;
}
