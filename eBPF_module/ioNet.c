#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define AF_INET 	2	
#define AF_INET6	10

#ifdef DEBUG
#define MAX_IP_STR_LEN 16
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct traffic_event_t {
    __u8 protocol;
    char direction;
    __u32 saddr;
    __u32 daddr;
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u16 sport;
    __u16 dport;
    __u32 ifindex;
    __u32 family;
    __u32 pkttype;
    __u64 bytes;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} traffic_ring SEC(".maps");

static __always_inline int parse_ports(void *transport, void *data_end, __u8 proto, __u16 *sport, __u16 *dport) {
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = transport;
        if ((void *)(tcph + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcph->source);
        *dport = bpf_ntohs(tcph->dest);
        return 0;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = transport;
        if ((void *)(udph + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udph->source);
        *dport = bpf_ntohs(udph->dest);
        return 0;
    }

    return -1; 
}


#ifdef DEBUG
static __always_inline void print_ip(__u32 ip, char *ip_str) {
    __u8 byte1 = (ip >> 24) & 0xFF;
    __u8 byte2 = (ip >> 16) & 0xFF;
    __u8 byte3 = (ip >> 8) & 0xFF;
    __u8 byte4 = ip & 0xFF;
    __u64 data[4] = {byte1, byte2, byte3, byte4};

    bpf_snprintf(ip_str, 16, "%u.%u.%u.%u", data,sizeof(data));
}
#endif

static __always_inline int parse_packet(struct __sk_buff *skb, bool is_ingress) {
    __u16 sport , dport ;
    __u8 proto = 0;
    __u32 saddr = 0;
    __u32 daddr = 0;
    __u8 saddr_v6[16] = {};
    __u8 daddr_v6[16] = {};
    __u32 family = skb->family;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (family == AF_INET) {
        struct iphdr *iph = data;
        if ((void *)(iph + 1) > data_end)
            return 0;

        proto = iph->protocol;
        saddr = iph->saddr;
        daddr = iph->daddr;

        void *transport = (void *)iph + iph->ihl * 4;
        if (transport + 4 > data_end)
            return 0;

        if (parse_ports(transport, data_end, proto, &sport, &dport) < 0){
            sport = 0;
            dport = 0;
        }
        
    } else if (family == AF_INET6) {
        struct ipv6hdr *ip6h = data;
        if ((void *)(ip6h + 1) > data_end)
            return 0;

        proto = ip6h->nexthdr;
        __builtin_memcpy(saddr_v6, &ip6h->saddr, 16);
        __builtin_memcpy(daddr_v6, &ip6h->daddr, 16);

        void *transport = (void *)(ip6h + 1);
        if (transport + 4 > data_end)
            return 0;

        if (parse_ports(transport, data_end, proto, &sport, &dport) < 0){
            sport = 0;
            dport = 0;
        }
    } else {
        sport = 0;
        dport = 0;
    }



    
    #ifdef DEBUG
    char src_ip_str[MAX_IP_STR_LEN];
    char dst_ip_str[MAX_IP_STR_LEN];
    print_ip(bpf_ntohl(saddr), src_ip_str);
    print_ip(bpf_ntohl(daddr), dst_ip_str);
    #endif
     
    struct traffic_event_t event = {
        .direction = is_ingress ? 'i' : 'o',
        .protocol = proto,
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .family = family,
        .pkttype = skb->pkt_type,
        .bytes = skb->len,
        .ifindex = skb->ifindex,
    };
    if (family == AF_INET6) {
        __builtin_memcpy(event.saddr_v6, saddr_v6, 16);
        __builtin_memcpy(event.daddr_v6, daddr_v6, 16);
    }

    #ifdef DEBUG
    bpf_printk("IP %s:%d -> %s:%d proto=%d  dir=%d len=%d type=%d fam=%d", src_ip_str, event.sport, dst_ip_str, event.dport ,
        event.protocol,  is_ingress , event.bytes ,event.pkttype,event.family
    );
    #endif
    
    if (bpf_ringbuf_output(&traffic_ring, &event, sizeof(event), BPF_RB_FORCE_WAKEUP)) {
        bpf_printk("Failed to send event to ringbuf");
    }

    return 0;
}

SEC("cgroup_skb/ingress")
int monitor_ingress(struct __sk_buff *skb) {
    parse_packet(skb, true);
    return 1;
}

SEC("cgroup_skb/egress")
int monitor_egress(struct __sk_buff *skb) {
    parse_packet(skb, false);
    return 1;
}

