#include <android/log.h>
#include <unistd.h>

#define TAG "InjectTest"

__attribute__((constructor))
static void on_load(void) {
    __android_log_print(ANDROID_LOG_INFO, TAG,
        "Payload loaded! pid=%d uid=%d", getpid(), getuid());
}
