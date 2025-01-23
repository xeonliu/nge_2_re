#include <pspkernel.h>

#include "patcher.h"
#include "transform.h"

PSP_MODULE_INFO("eva_patcher", PSP_MODULE_USER, 1, 1);

#include <pspiofilemgr.h>
#define LOG_FILE "ms0:/PSP/load_log.txt"
#define LOG(_id, value) { \
unsigned id = _id;\
SceUID f = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);\
if(f >= 0) { sceIoWrite(f, &id, sizeof(id)); sceIoWrite(f, &value, sizeof(value)); }\
sceIoClose(f);\
}

static int main_thread(SceSize args, void *argp) {
    // Patch The Function
    LOG(0, "Call Patch");
    patch();
    return sceKernelExitDeleteThread(0);
}

int module_start(SceSize args, void *argp) {
    SceUID thid = sceKernelCreateThread("patch_thread", main_thread, 0x18, 0x800, 0, NULL);
    if(thid >= 0) {
        sceKernelStartThread(thid, 0, NULL);
    }
    return 0;
}

int module_stop(SceSize args, void *argp) {
    return 0;
}