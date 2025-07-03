#include <pspkernel.h>

#include "patcher.h"
#include "transform.h"

PSP_MODULE_INFO("eva_patcher", PSP_MODULE_USER, 1, 1);

// Patcher Plugin needs to know the BASE ADDRESS of the game executable
// If it is not loaded to the default 0x08804000 address.

void _exit(int status)
{
    sceKernelExitGame();
}

static int main_thread(SceSize args, void *argp)
{
    // Module ID of the Game Executable
    SceUID eboot_mid = args >= 4 ? *(SceUID *)(argp) : -1;
    patch(eboot_mid);
    return sceKernelExitDeleteThread(0);
}

int module_start(SceSize args, void *argp)
{
    int th = sceKernelCreateThread("patcher", main_thread, 0x1F, 0x1000, 0, 0);
    if (th >= 0)
    {
        sceKernelStartThread(th, args, argp);
    }
    return 0;
}

int module_stop(SceSize args, void *argp)
{
    return 0;
}
