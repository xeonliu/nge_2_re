#include <pspkernel.h>

#include "patcher.h"
#include "transform.h"
#include "logger.h"

PSP_MODULE_INFO("eva_patcher", PSP_MODULE_USER, 1, 1);

// extern "C"
// {
//     int
//     main_thread(SceSize args, void *argp)
//     {
//       }
// }

// Patcher Plugin needs to know the BASE ADDRESS of the game executable
// If it is not loaded to the default 0x08804000 address.
extern "C"
{
    int
    module_start(SceSize args, void *argp)
    {
        // Patch The Function
        Logger::get_instance()->log("Patch Function");
        Patcher::get_instance()->patch();
        return 0;
        // SceUID thid = sceKernelCreateThread("patch_thread", main_thread, 0x18, 0x800, 0, NULL);
        // if (thid >= 0)
        // {
        //     sceKernelStartThread(thid, 0, NULL);
        // }
        // return 0;
    }
}

extern "C"
{
    int module_stop(SceSize args, void *argp)
    {
        return 0;
    }
}