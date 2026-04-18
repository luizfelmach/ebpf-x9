#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop;
static FILE *output_file;

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

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void mac_to_text(const __u8 mac[ETH_ALEN], char *out, size_t out_sz)
{
    snprintf(out,
             out_sz,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0],
             mac[1],
             mac[2],
             mac[3],
             mac[4],
             mac[5]);
}

static void tcp_flags_to_text(__u8 flags, char *out, size_t out_sz)
{
    size_t n = 0;

    if (!out_sz)
        return;

    if (flags & (1U << 1) && n + 1 < out_sz)
        out[n++] = 'S';
    if (flags & (1U << 4) && n + 1 < out_sz)
        out[n++] = 'A';
    if (flags & (1U << 3) && n + 1 < out_sz)
        out[n++] = 'P';
    if (flags & (1U << 2) && n + 1 < out_sz)
        out[n++] = 'R';
    if (flags & (1U << 0) && n + 1 < out_sz)
        out[n++] = 'F';
    if (flags & (1U << 5) && n + 1 < out_sz)
        out[n++] = 'U';
    if (flags & (1U << 6) && n + 1 < out_sz)
        out[n++] = 'E';
    if (flags & (1U << 7) && n + 1 < out_sz)
        out[n++] = 'C';

    if (!n && out_sz > 1)
        out[n++] = '-';

    out[n] = '\0';
}

static int on_event(void *ctx, void *data, size_t data_sz)
{
    const struct tc_event *event = data;
    char src_mac[18] = "-";
    char dst_mac[18] = "-";
    char src_ip[INET_ADDRSTRLEN] = "-";
    char dst_ip[INET_ADDRSTRLEN] = "-";
    char flags_text[16] = "-";

    (void)ctx;

    if (!output_file)
        return 0;
    if (data_sz < sizeof(*event))
        return 0;

    mac_to_text(event->src_mac, src_mac, sizeof(src_mac));
    mac_to_text(event->dst_mac, dst_mac, sizeof(dst_mac));
    tcp_flags_to_text(event->tcp_flags, flags_text, sizeof(flags_text));

    if (event->l3_proto == ETH_P_IP) {
        struct in_addr src = { .s_addr = event->src_ip };
        struct in_addr dst = { .s_addr = event->dst_ip };

        inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));
    }

    fprintf(output_file,
            "{\"ts_ns\":%llu,\"ifindex\":%u,\"ingress_ifindex\":%u,\"len\":%u,"
            "\"mark\":%u,\"priority\":%u,\"queue_mapping\":%u,\"protocol\":%u,"
            "\"pkt_type\":%u,\"tc_index\":%u,\"hash\":%u,\"tc_classid\":%u,"
            "\"vlan_present\":%u,\"vlan_tci\":%u,\"vlan_proto\":%u,\"l3_proto\":%u,"
            "\"src_mac\":\"%s\",\"dst_mac\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
            "\"ip_version\":%u,\"ip_ihl\":%u,\"ip_tot_len\":%u,\"ip_id\":%u,"
            "\"ip_frag_off\":%u,\"ip_proto\":%u,\"ip_ttl\":%u,\"ip_tos\":%u,\"ip_check\":%u,"
            "\"src_port\":%u,\"dst_port\":%u,\"tcp_seq\":%u,\"tcp_ack\":%u,\"tcp_window\":%u,"
            "\"tcp_urg_ptr\":%u,\"tcp_flags\":%u,\"tcp_flags_text\":\"%s\",\"tcp_doff\":%u,"
            "\"payload_len\":%u}\n",
            (unsigned long long)event->ts_ns,
            event->ifindex,
            event->ingress_ifindex,
            event->len,
            event->mark,
            event->priority,
            event->queue_mapping,
            event->protocol,
            event->pkt_type,
            event->tc_index,
            event->hash,
            event->tc_classid,
            event->vlan_present,
            event->vlan_tci,
            event->vlan_proto,
            event->l3_proto,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            event->ip_version,
            event->ip_ihl,
            event->ip_tot_len,
            event->ip_id,
            event->ip_frag_off,
            event->ip_proto,
            event->ip_ttl,
            event->ip_tos,
            event->ip_check,
            event->src_port,
            event->dst_port,
            event->tcp_seq,
            event->tcp_ack,
            event->tcp_window,
            event->tcp_urg_ptr,
            event->tcp_flags,
            flags_text,
            event->tcp_doff,
            event->payload_len);

    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = argc > 1 ? argv[1] : "eth0";
    const char *output_path = argc > 2 ? argv[2] : "/var/log/tc-events.ndjson";
    const char *bpf_obj_path = argc > 3 ? argv[3] : "x9.bpf.o";
    int ifindex = if_nametoindex(ifname);
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_tc_hook hook = { 0 };
    struct bpf_tc_opts attach_opts = { 0 };
    struct bpf_tc_opts detach_opts = { 0 };
    struct ring_buffer *rb = NULL;
    bool hook_created = false;
    int prog_fd;
    int map_fd;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (!ifindex) {
        fprintf(stderr, "invalid interface: %s\n", ifname);
        return 1;
    }

    output_file = fopen(output_path, "a");
    if (!output_file) {
        fprintf(stderr, "failed to open output file %s: %s\n", output_path, strerror(errno));
        return 1;
    }
    setvbuf(output_file, NULL, _IOLBF, 0);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object %s\n", bpf_obj_path);
        fclose(output_file);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "inspect_tc");
    if (!prog) {
        fprintf(stderr, "BPF program 'inspect_tc' not found\n");
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "failed to get program fd\n");
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "map 'events' not found\n");
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    rb = ring_buffer__new(map_fd, on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create event reader\n");
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "failed to create TC hook on %s: %s\n", ifname, strerror(-err));
        ring_buffer__free(rb);
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }
    if (!err)
        hook_created = true;

    attach_opts.sz = sizeof(attach_opts);
    attach_opts.prog_fd = prog_fd;
    attach_opts.handle = 1;
    attach_opts.priority = 1;
    attach_opts.flags = 0;

    err = bpf_tc_attach(&hook, &attach_opts);
    if (err == -EEXIST) {
        attach_opts.flags = BPF_TC_F_REPLACE;
        err = bpf_tc_attach(&hook, &attach_opts);
    }
    if (err) {
        fprintf(stderr, "failed to attach TC program on %s: %s\n", ifname, strerror(-err));
        if (hook_created)
            bpf_tc_hook_destroy(&hook);
        ring_buffer__free(rb);
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    detach_opts.sz = sizeof(detach_opts);
    detach_opts.handle = 1;
    detach_opts.priority = 1;

    printf("TC program attached on %s (ingress). Writing events to %s (Ctrl+C to exit)\n",
           ifname,
           output_path);
    while (!stop) {
        err = ring_buffer__poll(rb, 500);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "failed to read TC events: %d\n", err);
            break;
        }
    }

    bpf_tc_detach(&hook, &detach_opts);
    if (hook_created)
        bpf_tc_hook_destroy(&hook);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(output_file);
    return 0;
}
