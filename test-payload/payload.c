#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG "InjectTest"

static int g_counter = 0;

static void *counter_thread(void *arg) {
    (void)arg;
    while (1) {
        g_counter++;
        __android_log_print(ANDROID_LOG_INFO, TAG,
            "counter=%d pid=%d", g_counter, getpid());
        sleep(2);
    }
    return NULL;
}

static void dump_self_maps(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Failed to open /proc/self/maps");
        return;
    }

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strstr(line, "payload") ||
            (strstr(line, "memfd:") && !strstr(line, "jit-"))) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "VISIBLE: %s", line);
            found++;
        }
    }
    fclose(fp);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "maps check: payload NOT found in maps (hidden OK)");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "maps check: found %d entries (NOT hidden)", found);
    }
}

struct solist_ctx {
    int found;
    int total;
};

static int solist_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct solist_ctx *ctx = (struct solist_ctx *)data;
    const char *name = info->dlpi_name;

    if (!name || name[0] == '\0') {
        ctx->total++;
        return 0;
    }

    ctx->total++;

    if (strstr(name, "payload") || strstr(name, "memfd:")) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "solist VISIBLE: %s (base=%p)", name, (void *)info->dlpi_addr);
        ctx->found++;
    }

    return 0;
}

static void dump_solist(void) {
    struct solist_ctx ctx = { 0, 0 };
    dl_iterate_phdr(solist_callback, &ctx);

    if (ctx.found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "solist check: payload NOT found in solist (hidden OK), total=%d", ctx.total);
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "solist check: found %d entries in solist (NOT hidden), total=%d", ctx.found, ctx.total);
    }
}

static void dump_anon_exec(void) {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // 解析权限字段: "addr1-addr2 perms ..."
        char *perms = strchr(line, ' ');
        if (!perms) continue;
        perms++;

        // 需要有 x 权限
        if (strlen(perms) < 4 || perms[2] != 'x') continue;

        // 匿名映射：没有路径，或者路径部分为空
        // 跳过有文件路径的（包含 / 的）
        char *last_field = strrchr(line, ' ');
        if (!last_field) continue;
        last_field++;

        // 有路径的跳过（正常 so、vdso 等）
        if (last_field[0] == '/' || last_field[0] == '[') continue;

        // 跳过 jit 相关的
        if (strstr(line, "jit-")) continue;

        __android_log_print(ANDROID_LOG_WARN, TAG, "anon_exec: %s", line);
        found++;
    }
    fclose(fp);

    if (found == 0) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "anon_exec check: no suspicious anonymous executable regions");
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "anon_exec check: found %d anonymous executable regions", found);
    }
}

__attribute__((constructor))
static void init(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "Payload loaded (constructor)! pid=%d uid=%d", getpid(), getuid());
}

/// 注入器在 hide_maps 完成后远程调用此函数
__attribute__((visibility("default")))
int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "JNI_OnLoad called! pid=%d uid=%d", getpid(), getuid());

    dump_self_maps();
    dump_solist();
    dump_anon_exec();

    pthread_t tid;
    pthread_create(&tid, NULL, counter_thread, NULL);
    pthread_detach(tid);

    return 0x10006; // JNI_VERSION_1_6
}
