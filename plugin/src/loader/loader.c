#include <pspctrl.h>
#include <pspthreadman.h>
#include <pspmodulemgr.h>


#ifndef __cplusplus
#define EbootLoader "EbootLoader"
#endif
PSP_MODULE_INFO(EbootLoader, PSP_MODULE_USER, 1, 0);

#define PathOldBoot  "disc0:/PSP_GAME/SYSDIR/BOOT.BIN"
#define PathPrx "ms0:/PSP/patch.prx"

#include <pspiofilemgr.h>
#define LOG_FILE "ms0:/PSP/loader_log.txt"
#define LOG(_id, value) { \
unsigned id = _id;\
SceUID f = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);\
if(f >= 0) { sceIoWrite(f, &id, sizeof(id)); sceIoWrite(f, &value, sizeof(value)); }\
sceIoClose(f);\
}

static int main_thread(SceSize args, void *argp) {
	SceCtrlData pad;
	sceCtrlPeekBufferPositive(&pad, 1);

	char str_eboot[] = PathOldBoot;
	SceUID mid_eboot = sceKernelLoadModule(str_eboot, 0, NULL);
	LOG(0, mid_eboot);
	int stat_eboot;
	
    SceUID mid_prx = sceKernelLoadModule(PathPrx, 0, NULL);
    int stat_za;
    if (mid_prx >= 0) {
        sceKernelStartModule(mid_prx, sizeof(mid_eboot), &mid_eboot, &stat_za, NULL);
        LOG(1, "Start PRX Module");
    }
	
	if (mid_eboot >= 0) {
		sceKernelStartModule(mid_eboot, sizeof(str_eboot), str_eboot, &stat_eboot, NULL);
        LOG(1, "Start EBOOT Module");
	}

	return sceKernelExitDeleteThread(0);
}

#ifdef __cplusplus
extern "C"
#endif
int module_start (SceSize args, void* argp) {
	int th = sceKernelCreateThread("loader", main_thread, 0x1F, 0x1000, 0, 0);
	if (th >= 0) {
		sceKernelStartThread(th, args, argp);
	}
	return 0;
}

#ifdef __cplusplus
extern "C"
#endif
int module_stop (SceSize args, void *argp) {
    return 0;
}