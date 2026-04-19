#ifndef __X9_H
#define __X9_H

#include <linux/types.h>

#define X9_COMM_LEN 16
#define X9_ADDR_LEN 16

enum x9_event_type {
    X9_EVENT_CONNECT = 1,
    X9_EVENT_ACCEPT = 2,
};

struct x9_conn_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 type;
    __s32 fd;
    __s32 ret;
    __s32 flags;
    __u16 family;
    __u16 port;
    __u16 addrlen;
    __u8 addr[X9_ADDR_LEN];
    char comm[X9_COMM_LEN];
};

#endif
