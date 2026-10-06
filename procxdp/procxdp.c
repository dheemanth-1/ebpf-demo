//go:build ignore
 
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
 
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TCP_CLOSE 7
#define TCP_LISTEN 10
 
char __license[] SEC("license") = "Dual MIT/GPL";
 
struct comm_key {
    char name[16];
};
 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct comm_key);
    __type(value, __u16);
} allowed_ports SEC(".maps");
 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_ports SEC(".maps");
 

SEC("tracepoint/sock/inet_sock_set_state")
int track_listen(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }
 
    __u16 port = ctx->sport; // host byte order in this tracepoint
 
    if (ctx->newstate == TCP_LISTEN) {
        struct comm_key key = {};
        bpf_get_current_comm(key.name, sizeof(key.name));
 
        __u16 *allowed = bpf_map_lookup_elem(&allowed_ports, &key);
        if (allowed && *allowed != port) {
            __u8 one = 1;
            bpf_map_update_elem(&blocked_ports, &port, &one, BPF_ANY);
            bpf_printk("blocking port %d", port);
        } else if (allowed) {
            bpf_printk("allowing port %d", port);
        }
        
    } else if (ctx->oldstate == TCP_LISTEN && ctx->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&blocked_ports, &port);
    }
    return 0;
}
 

SEC("xdp")
int filter_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
 
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
 
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP || ip->ihl < 5) {
        return XDP_PASS;
    }
 
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }
 
    __u16 dport = bpf_ntohs(tcp->dest);
    return bpf_map_lookup_elem(&blocked_ports, &dport) ? XDP_DROP : XDP_PASS;
}
