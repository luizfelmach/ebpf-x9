#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "x9.h"

static volatile sig_atomic_t stop;
static FILE *output_file;

#define MAX_LINKS 16
#define CGROUP_SYNC_INTERVAL_SEC 5

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static const char *event_type_to_text(__u32 type)
{
    switch (type) {
    case X9_EVENT_CONNECT:
        return "connect";
    case X9_EVENT_ACCEPT:
        return "accept";
    default:
        return "unknown";
    }
}

static void format_address(const struct x9_conn_event *event, char *out, size_t out_sz)
{
    if (event->family == AF_INET) {
        struct in_addr addr4 = { 0 };

        memcpy(&addr4.s_addr, event->addr, sizeof(addr4.s_addr));
        if (inet_ntop(AF_INET, &addr4, out, out_sz))
            return;
    } else if (event->family == AF_INET6) {
        struct in6_addr addr6 = { 0 };

        memcpy(&addr6.s6_addr, event->addr, sizeof(addr6.s6_addr));
        if (inet_ntop(AF_INET6, &addr6, out, out_sz))
            return;
    }

    snprintf(out, out_sz, "-");
}

static unsigned long long monotonic_to_unix_ns(__u64 monotonic_ns)
{
    struct timespec realtime_ts = { 0 };
    struct timespec monotonic_ts = { 0 };
    unsigned long long realtime_ns;
    unsigned long long monotonic_now_ns;

    if (clock_gettime(CLOCK_REALTIME, &realtime_ts))
        return 0;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic_ts))
        return 0;

    realtime_ns = (unsigned long long)realtime_ts.tv_sec * 1000000000ULL +
                  (unsigned long long)realtime_ts.tv_nsec;
    monotonic_now_ns = (unsigned long long)monotonic_ts.tv_sec * 1000000000ULL +
                       (unsigned long long)monotonic_ts.tv_nsec;

    if (realtime_ns < monotonic_now_ns)
        return 0;

    return (realtime_ns - monotonic_now_ns) + (unsigned long long)monotonic_ns;
}

static void format_iso8601_utc(unsigned long long unix_ns, char *out, size_t out_sz)
{
    time_t sec;
    unsigned long nsec;
    struct tm tm_utc = { 0 };

    if (!unix_ns) {
        snprintf(out, out_sz, "-");
        return;
    }

    sec = (time_t)(unix_ns / 1000000000ULL);
    nsec = (unsigned long)(unix_ns % 1000000000ULL);

    if (!gmtime_r(&sec, &tm_utc)) {
        snprintf(out, out_sz, "-");
        return;
    }

    snprintf(out,
             out_sz,
             "%04d-%02d-%02dT%02d:%02d:%02d.%09luZ",
             tm_utc.tm_year + 1900,
             tm_utc.tm_mon + 1,
             tm_utc.tm_mday,
             tm_utc.tm_hour,
             tm_utc.tm_min,
             tm_utc.tm_sec,
             nsec);
}

struct cgroup_id_set {
    __u64 *ids;
    size_t count;
    size_t capacity;
};

static void cgroup_id_set_free(struct cgroup_id_set *set)
{
    free(set->ids);
    set->ids = NULL;
    set->count = 0;
    set->capacity = 0;
}

static bool cgroup_id_set_contains(const struct cgroup_id_set *set, __u64 id)
{
    for (size_t i = 0; i < set->count; i++) {
        if (set->ids[i] == id)
            return true;
    }
    return false;
}

static int cgroup_id_set_add_unique(struct cgroup_id_set *set, __u64 id)
{
    __u64 *new_ids;
    size_t new_capacity;

    if (!id)
        return 0;
    if (cgroup_id_set_contains(set, id))
        return 0;

    if (set->count == set->capacity) {
        new_capacity = set->capacity ? set->capacity * 2 : 128;
        new_ids = realloc(set->ids, new_capacity * sizeof(*new_ids));
        if (!new_ids)
            return -ENOMEM;
        set->ids = new_ids;
        set->capacity = new_capacity;
    }

    set->ids[set->count++] = id;
    return 0;
}

static bool is_directory(const char *path)
{
    struct stat st = { 0 };

    if (stat(path, &st))
        return false;
    return S_ISDIR(st.st_mode);
}

static int cgroup_id_from_path(const char *path, __u64 *id)
{
    struct {
        struct file_handle handle;
        unsigned char bytes[8];
    } handle = { 0 };
    struct stat st = { 0 };
    int mount_id = 0;

    handle.handle.handle_bytes = sizeof(handle.bytes);
    if (!name_to_handle_at(AT_FDCWD, path, &handle.handle, &mount_id, 0) &&
        handle.handle.handle_bytes == sizeof(handle.bytes)) {
        memcpy(id, handle.bytes, sizeof(*id));
        return 0;
    }

    if (!stat(path, &st)) {
        *id = (__u64)st.st_ino;
        return 0;
    }

    return -errno;
}

static bool path_is_kubepods_component(const char *path)
{
    const char *name = strrchr(path, '/');

    if (name)
        name++;
    else
        name = path;

    return strstr(name, "kubepods") != NULL;
}

static int scan_cgroup_tree(const char *root, struct cgroup_id_set *set, bool under_kubepods)
{
    DIR *dir;
    struct dirent *entry;
    int err;

    if (path_is_kubepods_component(root))
        under_kubepods = true;

    if (under_kubepods) {
        __u64 cgroup_id = 0;

        err = cgroup_id_from_path(root, &cgroup_id);
        if (err)
            return err;

        err = cgroup_id_set_add_unique(set, cgroup_id);
        if (err)
            return err;
    }

    dir = opendir(root);
    if (!dir) {
        if (errno == ENOENT || errno == EACCES)
            return 0;
        return -errno;
    }

    while ((entry = readdir(dir))) {
        struct stat st = { 0 };
        char child_path[PATH_MAX];

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        if (snprintf(child_path, sizeof(child_path), "%s/%s", root, entry->d_name) >=
            (int)sizeof(child_path))
            continue;

        if (lstat(child_path, &st))
            continue;
        if (!S_ISDIR(st.st_mode))
            continue;

        err = scan_cgroup_tree(child_path, set, under_kubepods);
        if (err && err != -ENOENT && err != -EACCES) {
            closedir(dir);
            return err;
        }
    }

    closedir(dir);
    return 0;
}

static int collect_kubernetes_cgroups(struct cgroup_id_set *set)
{
    static const char *bases[] = {
        "/host/sys/fs/cgroup",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/unified",
        "/sys/fs/cgroup/systemd",
    };
    bool found_base = false;
    int err;

    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        if (!is_directory(bases[i]))
            continue;
        found_base = true;
        err = scan_cgroup_tree(bases[i], set, false);
        if (err)
            return err;
    }

    if (!found_base || !set->count)
        return -ENOENT;

    return 0;
}

static int sync_allowed_cgroups(int map_fd, struct cgroup_id_set *active_set, bool *changed)
{
    struct cgroup_id_set next_set = { 0 };
    __u8 allow_value = 1;
    int err;

    if (changed)
        *changed = false;

    err = collect_kubernetes_cgroups(&next_set);
    if (err) {
        cgroup_id_set_free(&next_set);
        return err;
    }

    for (size_t i = 0; i < next_set.count; i++) {
        if (cgroup_id_set_contains(active_set, next_set.ids[i]))
            continue;
        if (bpf_map_update_elem(map_fd, &next_set.ids[i], &allow_value, BPF_ANY)) {
            err = -errno;
            cgroup_id_set_free(&next_set);
            return err;
        }
        if (changed)
            *changed = true;
    }

    for (size_t i = 0; i < active_set->count; i++) {
        if (cgroup_id_set_contains(&next_set, active_set->ids[i]))
            continue;
        if (bpf_map_delete_elem(map_fd, &active_set->ids[i]) && errno != ENOENT) {
            err = -errno;
            cgroup_id_set_free(&next_set);
            return err;
        }
        if (changed)
            *changed = true;
    }

    cgroup_id_set_free(active_set);
    *active_set = next_set;
    return 0;
}

static int on_event(void *ctx, void *data, size_t data_sz)
{
    const struct x9_conn_event *event = data;
    char addr_text[INET6_ADDRSTRLEN] = "-";
    char iso_ts[40] = "-";
    unsigned long long unix_ns;

    (void)ctx;

    if (!output_file)
        return 0;
    if (data_sz < sizeof(*event))
        return 0;

    format_address(event, addr_text, sizeof(addr_text));
    unix_ns = monotonic_to_unix_ns(event->ts_ns);
    format_iso8601_utc(unix_ns, iso_ts, sizeof(iso_ts));

    fprintf(output_file,
            "\"%llu\",\"%llu\",\"%s\",\"%s\",\"%u\",\"%u\",\"%u\",\"%s\",\"%d\",\"%d\",\"%d\",\"%u\",\"%s\",\"%u\",\"%u\"\n",
            (unsigned long long)event->ts_ns,
            unix_ns,
            iso_ts,
            event_type_to_text(event->type),
            event->pid,
            event->tid,
            event->uid,
            event->comm,
            event->fd,
            event->ret,
            event->flags,
            event->family,
            addr_text,
            event->port,
            event->addrlen);

    return 0;
}

int main(int argc, char **argv)
{
    const char *output_path = argc > 1 ? argv[1] : "/var/log/x9/events.csv";
    const char *bpf_obj_path = argc > 2 ? argv[2] : "x9.bpf.o";
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *links[MAX_LINKS] = { 0 };
    struct ring_buffer *rb = NULL;
    size_t link_count = 0;
    bool has_connect_enter = false;
    bool has_connect_exit = false;
    bool has_accept_enter = false;
    bool has_accept_exit = false;
    int map_fd;
    int allowed_cgroups_map_fd;
    struct cgroup_id_set synced_cgroups = { 0 };
    time_t next_cgroup_sync = 0;
    bool sync_changed = false;
    int err;

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

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

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "map 'events' not found\n");
        bpf_object__close(obj);
        fclose(output_file);
        return 1;
    }

    allowed_cgroups_map_fd = bpf_object__find_map_fd_by_name(obj, "allowed_cgroups");
    if (allowed_cgroups_map_fd < 0) {
        fprintf(stderr, "map 'allowed_cgroups' not found\n");
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

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link;
        const char *prog_name;

        if (link_count >= MAX_LINKS) {
            fprintf(stderr, "too many BPF programs; increase MAX_LINKS\n");
            err = -E2BIG;
            goto cleanup;
        }

        link = bpf_program__attach(prog);
        err = (int)libbpf_get_error(link);
        if (err) {
            if (err == -ENOENT || err == -ESRCH)
                continue;
            fprintf(stderr, "failed to attach program '%s': %s\n",
                    bpf_program__name(prog),
                    strerror(-err));
            goto cleanup;
        }

        prog_name = bpf_program__name(prog);
        if (!strncmp(prog_name, "kprobe_", 7) && strstr(prog_name, "_sys_connect"))
            has_connect_enter = true;
        else if (!strncmp(prog_name, "kretprobe_", 10) && strstr(prog_name, "_sys_connect"))
            has_connect_exit = true;
        else if (!strncmp(prog_name, "kprobe_", 7) && strstr(prog_name, "_sys_accept"))
            has_accept_enter = true;
        else if (!strncmp(prog_name, "kretprobe_", 10) && strstr(prog_name, "_sys_accept"))
            has_accept_exit = true;

        links[link_count++] = link;
    }

    if (!link_count) {
        fprintf(stderr, "no compatible kprobe could be attached\n");
        err = -ENOENT;
        goto cleanup;
    }

    if (!has_connect_enter || !has_connect_exit) {
        fprintf(stderr, "connect probes could not be attached on this kernel\n");
        err = -ENOENT;
        goto cleanup;
    }

    if (!has_accept_enter || !has_accept_exit) {
        fprintf(stderr, "accept probes could not be attached on this kernel\n");
        err = -ENOENT;
        goto cleanup;
    }

    err = sync_allowed_cgroups(allowed_cgroups_map_fd, &synced_cgroups, &sync_changed);
    if (err) {
        fprintf(stderr,
                "failed to load Kubernetes cgroup allowlist: %s\n",
                strerror(err < 0 ? -err : err));
        fprintf(stderr,
                "make sure host cgroups are visible at /host/sys/fs/cgroup or /sys/fs/cgroup\n");
        goto cleanup;
    }
    next_cgroup_sync = time(NULL) + CGROUP_SYNC_INTERVAL_SEC;
    printf("Loaded %zu Kubernetes cgroups into allowlist\n", synced_cgroups.count);

    err = 0;
    printf("Syscall kprobes attached. Writing events to %s (Ctrl+C to exit)\n", output_path);
    while (!stop) {
        time_t now = time(NULL);

        if (now >= next_cgroup_sync) {
            sync_changed = false;
            err = sync_allowed_cgroups(allowed_cgroups_map_fd, &synced_cgroups, &sync_changed);
            if (err) {
                fprintf(stderr,
                        "failed to refresh Kubernetes cgroup allowlist: %s\n",
                        strerror(err < 0 ? -err : err));
                break;
            }
            if (sync_changed)
                printf("Refreshed Kubernetes cgroup allowlist: %zu entries\n", synced_cgroups.count);
            next_cgroup_sync = now + CGROUP_SYNC_INTERVAL_SEC;
        }

        err = ring_buffer__poll(rb, 500);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "failed to read syscall events: %d\n", err);
            break;
        }
    }

cleanup:
    for (size_t i = 0; i < link_count; i++)
        bpf_link__destroy(links[i]);
    cgroup_id_set_free(&synced_cgroups);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(output_file);

    if (err)
        return 1;
    return 0;
}
