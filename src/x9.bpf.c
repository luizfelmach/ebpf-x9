#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ptrace.h>
#include <linux/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "x9.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct sockaddr_in_user {
    __u16 sin_family;
    __be16 sin_port;
    __u32 sin_addr;
    __u8 sin_zero[8];
};

struct sockaddr_in6_user {
    __u16 sin6_family;
    __be16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

struct connect_args {
    __s32 fd;
    __s32 addrlen;
    __u64 user_sockaddr;
    __u32 uid;
    char comm[X9_COMM_LEN];
};

struct accept_args {
    __s32 fd;
    __s32 flags;
    __u64 user_sockaddr;
    __u64 user_addrlen;
    __u32 uid;
    char comm[X9_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct connect_args);
    __uint(max_entries, 16384);
} connect_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct accept_args);
    __uint(max_entries, 16384);
} accept_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8);
    __uint(max_entries, 131072);
} allowed_cgroups SEC(".maps");

static __always_inline int is_allowed_cgroup(void)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *allowed;

    if (!cgroup_id)
        return 0;

    allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
    if (!allowed || !*allowed)
        return 0;
    return 1;
}

static __always_inline __u16 clamp_addrlen(__u32 addrlen)
{
    if (addrlen > 0xffff)
        return 0xffff;
    return (__u16)addrlen;
}

static __always_inline void fill_address(__u64 user_sockaddr, __u32 addrlen, struct x9_conn_event *event)
{
    __u16 family;

    if (!user_sockaddr || addrlen < sizeof(family))
        return;

    if (bpf_probe_read_user(&family, sizeof(family), (void *)(long)user_sockaddr))
        return;

    event->family = family;
    event->addrlen = clamp_addrlen(addrlen);

    if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in_user)) {
        struct sockaddr_in_user sa4;

        if (!bpf_probe_read_user(&sa4, sizeof(sa4), (void *)(long)user_sockaddr)) {
            event->port = bpf_ntohs(sa4.sin_port);
            __builtin_memcpy(event->addr, &sa4.sin_addr, sizeof(sa4.sin_addr));
        }
        return;
    }

    if (family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6_user)) {
        struct sockaddr_in6_user sa6;

        if (!bpf_probe_read_user(&sa6, sizeof(sa6), (void *)(long)user_sockaddr)) {
            event->port = bpf_ntohs(sa6.sin6_port);
            __builtin_memcpy(event->addr, sa6.sin6_addr, sizeof(sa6.sin6_addr));
        }
    }
}

static __always_inline void fill_identity(struct x9_conn_event *event, __u64 pid_tgid, __u32 uid, const char comm[X9_COMM_LEN])
{
    event->ts_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = uid;
    __builtin_memcpy(event->comm, comm, X9_COMM_LEN);
}

static __always_inline int save_connect_args(__s32 fd, __u64 user_sockaddr, __s32 addrlen)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_args args = {};

    args.fd = fd;
    args.user_sockaddr = user_sockaddr;
    args.addrlen = addrlen;
    args.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(args.comm, sizeof(args.comm));
    bpf_map_update_elem(&connect_inflight, &pid_tgid, &args, BPF_ANY);
    return 0;
}

static __always_inline int submit_connect_event(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_args *args;
    struct x9_conn_event *event;

    args = bpf_map_lookup_elem(&connect_inflight, &pid_tgid);
    if (!args)
        return 0;

    if (ret == 0 && is_allowed_cgroup()) {
        __u32 addrlen = args->addrlen > 0 ? (__u32)args->addrlen : 0;

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            fill_identity(event, pid_tgid, args->uid, args->comm);
            event->type = X9_EVENT_CONNECT;
            event->fd = args->fd;
            event->ret = (__s32)ret;
            fill_address(args->user_sockaddr, addrlen, event);
            bpf_ringbuf_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&connect_inflight, &pid_tgid);
    return 0;
}

static __always_inline int save_accept_args(__s32 fd, __u64 user_sockaddr, __u64 user_addrlen, __s32 flags)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args args = {};

    args.fd = fd;
    args.user_sockaddr = user_sockaddr;
    args.user_addrlen = user_addrlen;
    args.flags = flags;
    args.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(args.comm, sizeof(args.comm));
    bpf_map_update_elem(&accept_inflight, &pid_tgid, &args, BPF_ANY);
    return 0;
}

static __always_inline int submit_accept_event(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args *args;
    struct x9_conn_event *event;
    __u32 addrlen = 0;

    args = bpf_map_lookup_elem(&accept_inflight, &pid_tgid);
    if (!args)
        return 0;

    if (ret >= 0 && is_allowed_cgroup()) {
        if (args->user_addrlen) {
            __u32 len = 0;

            if (!bpf_probe_read_user(&len, sizeof(len), (void *)(long)args->user_addrlen))
                addrlen = len;
        }

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            fill_identity(event, pid_tgid, args->uid, args->comm);
            event->type = X9_EVENT_ACCEPT;
            event->fd = args->fd;
            event->ret = (__s32)ret;
            event->flags = args->flags;
            fill_address(args->user_sockaddr, addrlen, event);
            bpf_ringbuf_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&accept_inflight, &pid_tgid);
    return 0;
}

SEC("kprobe/__sys_connect")
int kprobe_sys_connect(struct pt_regs *ctx)
{
    return save_connect_args((__s32)PT_REGS_PARM1(ctx),
                             (__u64)PT_REGS_PARM2(ctx),
                             (__s32)PT_REGS_PARM3(ctx));
}

SEC("kretprobe/__sys_connect")
int kretprobe_sys_connect(struct pt_regs *ctx)
{
    return submit_connect_event(PT_REGS_RC(ctx));
}

SEC("kprobe/__sys_accept4")
int kprobe_sys_accept4(struct pt_regs *ctx)
{
    return save_accept_args((__s32)PT_REGS_PARM1(ctx),
                             (__u64)PT_REGS_PARM2(ctx),
                             (__u64)PT_REGS_PARM3(ctx),
                             (__s32)PT_REGS_PARM4(ctx));
}

SEC("kretprobe/__sys_accept4")
int kretprobe_sys_accept4(struct pt_regs *ctx)
{
    return submit_accept_event(PT_REGS_RC(ctx));
}

char LICENSE[] SEC("license") = "GPL";
