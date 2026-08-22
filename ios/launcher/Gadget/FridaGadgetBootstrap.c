#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char ob_image_anchor;

static void ob_load_gadget(void *context) {
    char *path = context;
    if (dlopen(path, RTLD_NOW | RTLD_LOCAL) == NULL)
        fprintf(stderr, "OpenBachelor bootstrap: dlopen failed: %s\n", dlerror());
    free(path);
}

__attribute__((constructor))
static void ob_schedule_gadget_load(void) {
    Dl_info image;
    if (dladdr(&ob_image_anchor, &image) == 0 || image.dli_fname == NULL) return;

    const char *separator = strrchr(image.dli_fname, '/');
    static const char payload_name[] = "/FridaGadgetCore.dylib";
    if (separator == NULL) return;
    size_t directory_length = (size_t)(separator - image.dli_fname);
    if (directory_length + sizeof(payload_name) > PATH_MAX) return;

    char path[PATH_MAX];
    memcpy(path, image.dli_fname, directory_length);
    memcpy(path + directory_length, payload_name, sizeof(payload_name));
    char *owned_path = strdup(path);
    if (owned_path == NULL) return;

    // Returning from this constructor lets the application finish its early
    // signal/runtime setup before Frida Gum installs its exception backend.
    dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                     dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                     owned_path, ob_load_gadget);
}
