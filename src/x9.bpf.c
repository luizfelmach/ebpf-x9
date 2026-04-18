#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct tc_event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 ingress_ifindex;
    __u32 len;
    __u32 mark;
    __u32 priority;
    __u32 queue_mapping;
    __u16 protocol;
    __u8 pkt_type;
    __u8 tc_index;
    __u32 hash;
    __u32 tc_classid;
    __u16 vlan_tci;
    __u16 vlan_proto;
    __u8 vlan_present;
    __u8 pad0;
    __u16 l3_proto;
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u8 ip_version;
    __u8 ip_ihl;
    __u16 ip_tot_len;
    __u16 ip_id;
    __u16 ip_frag_off;
    __u8 ip_proto;
    __u8 ip_ttl;
    __u8 ip_tos;
    __u8 pad1;
    __u16 ip_check;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_window;
    __u16 tcp_urg_ptr;
    __u8 tcp_flags;
    __u8 tcp_doff;
    __u16 payload_len;
};

static __always_inline void fill_payload_len(void *payload, void *data_end, struct tc_event *event)
{
    __u64 payload_bytes;

    if (payload > data_end)
        return;

    payload_bytes = (__u64)((long)data_end - (long)payload);
    event->payload_len = payload_bytes > 0xffff ? 0xffff : (__u16)payload_bytes;
}

static __always_inline void fill_ipv4_fields(struct iphdr *iph, struct tc_event *event)
{
    event->ip_version = iph->version;
    event->ip_ihl = iph->ihl;
    event->ip_tot_len = bpf_ntohs(iph->tot_len);
    event->ip_id = bpf_ntohs(iph->id);
    event->ip_frag_off = bpf_ntohs(iph->frag_off);
    event->ip_proto = iph->protocol;
    event->ip_ttl = iph->ttl;
    event->ip_tos = iph->tos;
    event->ip_check = bpf_ntohs(iph->check);
    event->src_ip = iph->saddr;
    event->dst_ip = iph->daddr;
}

static __always_inline void fill_tcp_fields(struct tcphdr *tcph, void *data_end, struct tc_event *event)
{
    __u16 doff = tcph->doff * 4;
    void *payload;

    event->src_port = bpf_ntohs(tcph->source);
    event->dst_port = bpf_ntohs(tcph->dest);
    event->tcp_seq = bpf_ntohl(tcph->seq);
    event->tcp_ack = bpf_ntohl(tcph->ack_seq);
    event->tcp_window = bpf_ntohs(tcph->window);
    event->tcp_urg_ptr = bpf_ntohs(tcph->urg_ptr);
    event->tcp_flags = ((__u8)tcph->fin) |
                       ((__u8)tcph->syn << 1) |
                       ((__u8)tcph->rst << 2) |
                       ((__u8)tcph->psh << 3) |
                       ((__u8)tcph->ack << 4) |
                       ((__u8)tcph->urg << 5) |
                       ((__u8)tcph->ece << 6) |
                       ((__u8)tcph->cwr << 7);
    event->tcp_doff = tcph->doff;

    if (doff < sizeof(*tcph))
        return;

    payload = (void *)tcph + doff;
    fill_payload_len(payload, data_end, event);
}

SEC("tc")
int inspect_tc(struct __sk_buff *skb)
{
    struct tc_event *event;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;

    __builtin_memset(event, 0, sizeof(*event));
    event->ts_ns = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    event->ingress_ifindex = skb->ingress_ifindex;
    event->len = skb->len;
    event->mark = skb->mark;
    event->priority = skb->priority;
    event->queue_mapping = skb->queue_mapping;
    event->protocol = bpf_ntohs(skb->protocol);
    event->pkt_type = skb->pkt_type;
    event->tc_index = skb->tc_index;
    event->hash = skb->hash;
    event->tc_classid = skb->tc_classid;
    event->vlan_present = skb->vlan_present;
    event->vlan_tci = skb->vlan_tci;
    event->vlan_proto = bpf_ntohs(skb->vlan_proto);

    if ((void *)(eth + 1) <= data_end) {
        __u16 l3_proto = bpf_ntohs(eth->h_proto);

        __builtin_memcpy(event->src_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(event->dst_mac, eth->h_dest, ETH_ALEN);
        event->l3_proto = l3_proto;

        if (l3_proto == ETH_P_IP) {
            struct iphdr *iph = (void *)(eth + 1);

            if ((void *)(iph + 1) <= data_end) {
                fill_ipv4_fields(iph, event);

                if (iph->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);

                    if ((void *)(tcph + 1) <= data_end)
                        fill_tcp_fields(tcph, data_end, event);
                }
            }
        }
    }

    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
