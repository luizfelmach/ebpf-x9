#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
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
#define X9_POD_UID_LEN 37
#define X9_POD_NAMESPACE_LEN 64
#define X9_POD_NAME_LEN 256

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

static void json_write_escaped_string(FILE *file, const char *text)
{
    const unsigned char *p = (const unsigned char *)text;

    fputc('"', file);
    if (!text) {
        fputc('"', file);
        return;
    }

    while (*p) {
        switch (*p) {
        case '"':
            fputs("\\\"", file);
            break;
        case '\\':
            fputs("\\\\", file);
            break;
        case '\b':
            fputs("\\b", file);
            break;
        case '\f':
            fputs("\\f", file);
            break;
        case '\n':
            fputs("\\n", file);
            break;
        case '\r':
            fputs("\\r", file);
            break;
        case '\t':
            fputs("\\t", file);
            break;
        default:
            if (*p < 0x20)
                fprintf(file, "\\u%04x", (unsigned int)*p);
            else
                fputc(*p, file);
            break;
        }
        p++;
    }

    fputc('"', file);
}

struct cgroup_entry {
    __u64 id;
    char pod_uid[X9_POD_UID_LEN];
};

struct cgroup_id_set {
    struct cgroup_entry *entries;
    size_t count;
    size_t capacity;
};

struct pod_identity {
    char uid[X9_POD_UID_LEN];
    char namespace[X9_POD_NAMESPACE_LEN];
    char name[X9_POD_NAME_LEN];
};

struct pod_identity_set {
    struct pod_identity *items;
    size_t count;
    size_t capacity;
};

struct runtime_metadata {
    const struct cgroup_id_set *cgroups;
    const struct pod_identity_set *pods;
};

static void cgroup_id_set_free(struct cgroup_id_set *set)
{
    free(set->entries);
    set->entries = NULL;
    set->count = 0;
    set->capacity = 0;
}

static struct cgroup_entry *cgroup_id_set_find_entry(struct cgroup_id_set *set, __u64 id)
{
    for (size_t i = 0; i < set->count; i++) {
        if (set->entries[i].id == id)
            return &set->entries[i];
    }
    return NULL;
}

static const struct cgroup_entry *cgroup_id_set_find_entry_const(const struct cgroup_id_set *set, __u64 id)
{
    for (size_t i = 0; i < set->count; i++) {
        if (set->entries[i].id == id)
            return &set->entries[i];
    }
    return NULL;
}

static bool cgroup_id_set_contains(const struct cgroup_id_set *set, __u64 id)
{
    return cgroup_id_set_find_entry_const(set, id) != NULL;
}

static const char *cgroup_id_set_lookup_pod_uid(const struct cgroup_id_set *set, __u64 id)
{
    const struct cgroup_entry *entry = cgroup_id_set_find_entry_const(set, id);

    if (!entry || !entry->pod_uid[0])
        return NULL;
    return entry->pod_uid;
}

static int cgroup_id_set_add_unique(struct cgroup_id_set *set, __u64 id, const char *pod_uid)
{
    struct cgroup_entry *existing;
    struct cgroup_entry *new_entries;
    size_t new_capacity;

    if (!id)
        return 0;
    existing = cgroup_id_set_find_entry(set, id);
    if (existing) {
        if (!existing->pod_uid[0] && pod_uid && pod_uid[0])
            snprintf(existing->pod_uid, sizeof(existing->pod_uid), "%s", pod_uid);
        return 0;
    }

    if (set->count == set->capacity) {
        new_capacity = set->capacity ? set->capacity * 2 : 128;
        new_entries = realloc(set->entries, new_capacity * sizeof(*new_entries));
        if (!new_entries)
            return -ENOMEM;
        set->entries = new_entries;
        set->capacity = new_capacity;
    }

    set->entries[set->count].id = id;
    set->entries[set->count].pod_uid[0] = '\0';
    if (pod_uid && pod_uid[0])
        snprintf(set->entries[set->count].pod_uid, sizeof(set->entries[set->count].pod_uid), "%s", pod_uid);
    set->count++;

    return 0;
}

static void pod_identity_set_free(struct pod_identity_set *set)
{
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

static struct pod_identity *pod_identity_set_find(struct pod_identity_set *set, const char *uid)
{
    for (size_t i = 0; i < set->count; i++) {
        if (!strcmp(set->items[i].uid, uid))
            return &set->items[i];
    }
    return NULL;
}

static const struct pod_identity *pod_identity_set_lookup(const struct pod_identity_set *set, const char *uid)
{
    for (size_t i = 0; i < set->count; i++) {
        if (!strcmp(set->items[i].uid, uid))
            return &set->items[i];
    }
    return NULL;
}

static int pod_identity_set_add_or_update(struct pod_identity_set *set,
                                          const char *uid,
                                          const char *namespace,
                                          const char *name)
{
    struct pod_identity *entry;
    struct pod_identity *new_items;
    size_t new_capacity;

    if (!uid || !uid[0] || !namespace || !namespace[0] || !name || !name[0])
        return 0;

    entry = pod_identity_set_find(set, uid);
    if (entry) {
        snprintf(entry->namespace, sizeof(entry->namespace), "%s", namespace);
        snprintf(entry->name, sizeof(entry->name), "%s", name);
        return 0;
    }

    if (set->count == set->capacity) {
        new_capacity = set->capacity ? set->capacity * 2 : 128;
        new_items = realloc(set->items, new_capacity * sizeof(*new_items));
        if (!new_items)
            return -ENOMEM;
        set->items = new_items;
        set->capacity = new_capacity;
    }

    entry = &set->items[set->count++];
    snprintf(entry->uid, sizeof(entry->uid), "%s", uid);
    snprintf(entry->namespace, sizeof(entry->namespace), "%s", namespace);
    snprintf(entry->name, sizeof(entry->name), "%s", name);
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

static bool normalize_pod_uid(const char *candidate, char out[X9_POD_UID_LEN])
{
    char hex[33] = { 0 };
    size_t hex_len = 0;

    if (!candidate || !candidate[0])
        return false;

    for (const char *p = candidate; *p; p++) {
        unsigned char c = (unsigned char)*p;

        if (isxdigit(c)) {
            if (hex_len >= sizeof(hex) - 1)
                return false;
            hex[hex_len++] = (char)tolower(c);
            continue;
        }
        if (c == '-' || c == '_')
            continue;
        return false;
    }

    if (hex_len != 32)
        return false;

    snprintf(out,
             X9_POD_UID_LEN,
             "%.8s-%.4s-%.4s-%.4s-%.12s",
             hex,
             hex + 8,
             hex + 12,
             hex + 16,
             hex + 20);
    return true;
}

static bool extract_pod_uid_from_component(const char *component, char out[X9_POD_UID_LEN])
{
    const char *cursor = component;

    if (!component)
        return false;

    while ((cursor = strstr(cursor, "pod")) != NULL) {
        char candidate[80] = { 0 };
        size_t candidate_len = 0;

        for (const char *p = cursor + 3; *p; p++) {
            unsigned char c = (unsigned char)*p;

            if (isxdigit(c) || c == '-' || c == '_') {
                if (candidate_len + 1 >= sizeof(candidate))
                    break;
                candidate[candidate_len++] = (char)c;
                continue;
            }
            break;
        }

        candidate[candidate_len] = '\0';
        if (normalize_pod_uid(candidate, out))
            return true;
        cursor += 3;
    }

    return false;
}

static bool extract_pod_uid_from_path(const char *path, char out[X9_POD_UID_LEN])
{
    const char *start = path;
    bool found = false;

    if (!path)
        return false;

    while (*start) {
        const char *end;
        size_t len;
        char component[NAME_MAX + 1] = { 0 };

        while (*start == '/')
            start++;
        if (!*start)
            break;

        end = strchr(start, '/');
        len = end ? (size_t)(end - start) : strlen(start);
        if (len >= sizeof(component))
            len = sizeof(component) - 1;
        memcpy(component, start, len);
        component[len] = '\0';

        if (extract_pod_uid_from_component(component, out))
            found = true;

        if (!end)
            break;
        start = end;
    }

    return found;
}

static int scan_cgroup_tree(const char *root,
                            struct cgroup_id_set *set,
                            bool under_kubepods,
                            const char *parent_pod_uid)
{
    DIR *dir;
    struct dirent *entry;
    char current_pod_uid[X9_POD_UID_LEN] = { 0 };
    char path_pod_uid[X9_POD_UID_LEN] = { 0 };
    int err;

    if (parent_pod_uid && parent_pod_uid[0])
        snprintf(current_pod_uid, sizeof(current_pod_uid), "%s", parent_pod_uid);

    if (path_is_kubepods_component(root))
        under_kubepods = true;
    if (extract_pod_uid_from_path(root, path_pod_uid))
        snprintf(current_pod_uid, sizeof(current_pod_uid), "%s", path_pod_uid);

    if (under_kubepods) {
        __u64 cgroup_id = 0;

        err = cgroup_id_from_path(root, &cgroup_id);
        if (err)
            return err;

        err = cgroup_id_set_add_unique(set, cgroup_id, current_pod_uid);
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

        err = scan_cgroup_tree(child_path, set, under_kubepods, current_pod_uid);
        if (err && err != -ENOENT && err != -EACCES) {
            closedir(dir);
            return err;
        }
    }

    closedir(dir);
    return 0;
}

static bool parse_pod_log_directory_name(const char *name,
                                         char uid[X9_POD_UID_LEN],
                                         char namespace[X9_POD_NAMESPACE_LEN],
                                         char pod_name[X9_POD_NAME_LEN])
{
    const char *first_sep;
    const char *last_sep;
    size_t namespace_len;
    size_t pod_len;
    char uid_candidate[80] = { 0 };

    if (!name || !name[0])
        return false;

    first_sep = strchr(name, '_');
    last_sep = strrchr(name, '_');
    if (!first_sep || !last_sep || first_sep == last_sep)
        return false;

    namespace_len = (size_t)(first_sep - name);
    pod_len = (size_t)(last_sep - first_sep - 1);
    if (!namespace_len || !pod_len)
        return false;
    if (namespace_len >= X9_POD_NAMESPACE_LEN || pod_len >= X9_POD_NAME_LEN)
        return false;

    if (snprintf(uid_candidate, sizeof(uid_candidate), "%s", last_sep + 1) >= (int)sizeof(uid_candidate))
        return false;
    if (!normalize_pod_uid(uid_candidate, uid))
        return false;

    memcpy(namespace, name, namespace_len);
    namespace[namespace_len] = '\0';
    memcpy(pod_name, first_sep + 1, pod_len);
    pod_name[pod_len] = '\0';
    return true;
}

static int scan_pod_logs(const char *root, struct pod_identity_set *set)
{
    DIR *dir;
    struct dirent *entry;

    dir = opendir(root);
    if (!dir) {
        if (errno == ENOENT || errno == EACCES)
            return 0;
        return -errno;
    }

    while ((entry = readdir(dir))) {
        struct stat st = { 0 };
        char path[PATH_MAX];
        char uid[X9_POD_UID_LEN] = { 0 };
        char namespace[X9_POD_NAMESPACE_LEN] = { 0 };
        char pod_name[X9_POD_NAME_LEN] = { 0 };
        int err;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", root, entry->d_name) >= (int)sizeof(path))
            continue;
        if (lstat(path, &st))
            continue;
        if (!S_ISDIR(st.st_mode))
            continue;

        if (!parse_pod_log_directory_name(entry->d_name, uid, namespace, pod_name))
            continue;

        err = pod_identity_set_add_or_update(set, uid, namespace, pod_name);
        if (err) {
            closedir(dir);
            return err;
        }
    }

    closedir(dir);
    return 0;
}

static int refresh_pod_identities(struct pod_identity_set *set)
{
    static const char *bases[] = {
        "/host/var/log/pods",
        "/var/log/pods",
    };
    struct pod_identity_set next_set = { 0 };
    bool found_base = false;
    int err;

    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        if (!is_directory(bases[i]))
            continue;
        found_base = true;
        err = scan_pod_logs(bases[i], &next_set);
        if (err) {
            pod_identity_set_free(&next_set);
            return err;
        }
    }

    if (!found_base)
        pod_identity_set_free(&next_set);

    pod_identity_set_free(set);
    *set = next_set;
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
        err = scan_cgroup_tree(bases[i], set, false, NULL);
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
        __u64 cgroup_id = next_set.entries[i].id;

        if (cgroup_id_set_contains(active_set, cgroup_id))
            continue;
        if (bpf_map_update_elem(map_fd, &cgroup_id, &allow_value, BPF_ANY)) {
            err = -errno;
            cgroup_id_set_free(&next_set);
            return err;
        }
        if (changed)
            *changed = true;
    }

    for (size_t i = 0; i < active_set->count; i++) {
        __u64 cgroup_id = active_set->entries[i].id;

        if (cgroup_id_set_contains(&next_set, cgroup_id))
            continue;
        if (bpf_map_delete_elem(map_fd, &cgroup_id) && errno != ENOENT) {
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
    const struct runtime_metadata *metadata = ctx;
    const struct x9_conn_event *event = data;
    char addr_text[INET6_ADDRSTRLEN] = "-";
    char iso_ts[40] = "-";
    char pod_namespace[X9_POD_NAMESPACE_LEN] = "-";
    char pod_name[X9_POD_NAME_LEN] = "-";
    const char *pod_uid;
    const struct pod_identity *pod_identity;
    unsigned long long unix_ns;

    if (!output_file)
        return 0;
    if (data_sz < sizeof(*event))
        return 0;

    format_address(event, addr_text, sizeof(addr_text));
    unix_ns = monotonic_to_unix_ns(event->ts_ns);
    format_iso8601_utc(unix_ns, iso_ts, sizeof(iso_ts));

    pod_uid = NULL;
    pod_identity = NULL;
    if (metadata && metadata->cgroups)
        pod_uid = cgroup_id_set_lookup_pod_uid(metadata->cgroups, event->cgroup_id);
    if (pod_uid && metadata && metadata->pods)
        pod_identity = pod_identity_set_lookup(metadata->pods, pod_uid);
    if (pod_identity) {
        snprintf(pod_namespace, sizeof(pod_namespace), "%s", pod_identity->namespace);
        snprintf(pod_name, sizeof(pod_name), "%s", pod_identity->name);
    }

    fprintf(output_file,
            "{\"ts_ns\":%llu,\"unix_ns\":%llu,\"iso_ts\":",
            (unsigned long long)event->ts_ns,
            unix_ns);
    json_write_escaped_string(output_file, iso_ts);
    fputs(",\"event_type\":", output_file);
    json_write_escaped_string(output_file, event_type_to_text(event->type));
    fprintf(output_file,
            ",\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":",
            event->pid,
            event->tid,
            event->uid);
    json_write_escaped_string(output_file, event->comm);
    fprintf(output_file,
            ",\"fd\":%d,\"ret\":%d,\"flags\":%d,\"family\":%u,\"addr\":",
            event->fd,
            event->ret,
            event->flags,
            event->family);
    json_write_escaped_string(output_file, addr_text);
    fprintf(output_file,
            ",\"port\":%u,\"addrlen\":%u,\"pod_namespace\":",
            event->port,
            event->addrlen);
    json_write_escaped_string(output_file, pod_namespace);
    fputs(",\"pod_name\":", output_file);
    json_write_escaped_string(output_file, pod_name);
    fputs("}\n", output_file);

    return 0;
}

int main(int argc, char **argv)
{
    const char *output_path = argc > 1 ? argv[1] : "/var/log/x9/events.json";
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
    struct pod_identity_set pod_identities = { 0 };
    struct runtime_metadata metadata = {
        .cgroups = &synced_cgroups,
        .pods = &pod_identities,
    };
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

    rb = ring_buffer__new(map_fd, on_event, &metadata, NULL);
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

    {
        int pods_err = refresh_pod_identities(&pod_identities);

        if (pods_err) {
            fprintf(stderr,
                    "failed to load pod metadata from /host/var/log/pods: %s\n",
                    strerror(pods_err < 0 ? -pods_err : pods_err));
        } else if (pod_identities.count) {
            printf("Loaded %zu pod identities\n", pod_identities.count);
        }
    }

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

            {
                int pods_err = refresh_pod_identities(&pod_identities);

                if (pods_err) {
                    fprintf(stderr,
                            "failed to refresh pod metadata from /host/var/log/pods: %s\n",
                            strerror(pods_err < 0 ? -pods_err : pods_err));
                }
            }

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
    pod_identity_set_free(&pod_identities);
    cgroup_id_set_free(&synced_cgroups);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(output_file);

    if (err)
        return 1;
    return 0;
}
