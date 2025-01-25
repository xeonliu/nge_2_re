#include <pspkernel.h>

#include "patcher.h"
#include "transform.h"
#include "log.h"

PSP_MODULE_INFO("eva_patcher", PSP_MODULE_USER, 1, 1);
PSP_NO_CREATE_MAIN_THREAD();

static SceModule *findUserMainModule();

static int main_thread(SceSize args, void *argp)
{
    // Wait for USER_MAIN to load
    sceKernelDelayThread(10000);

    SceModule *main_module = findUserMainModule();
    if (main_module == NULL)
    {
        dbg_log("Failed to find USER_MAIN module\n");
    }

    SceKernelModuleInfo info;
    if (sceKernelQueryModuleInfo(main_module->modid, &info))
    {
        dbg_log("Failed to query module info\n");
    }
    // This Seems to be the real Base Address in PPSSPP
    u32 base_addr = info.segmentaddr[0];
    dbg_log("BaseAddr of USER_MAIN In SceKernelModuleInfo: %x\n", base_addr);
    dbg_log("Patcher Thread Started, mod_base: %x\n", base_addr);
    patch(base_addr);
    return sceKernelExitDeleteThread(0);
}

int module_start(SceSize args, void *argp)
{
    SceUID thid = sceKernelCreateThread("patch_thread", main_thread, 0x30, 0x10000, 0, NULL);
    if (thid >= 0)
    {
        sceKernelStartThread(thid, 0, NULL);
    }
    return 0;
}

int module_stop(SceSize args, void *argp)
{
    return 0;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    while (n--)
    {
        if (*s1 != *s2)
        {
            return *(unsigned char *)s1 - *(unsigned char *)s2;
        }
        if (*s1 == '\0')
        {
            return 0;
        }
        s1++;
        s2++;
    }
    return 0;
}

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
    {
        *p++ = (unsigned char)c;
    }
    return s;
}

static SceModule *findUserMainModule()
{
    SceUID ids[512];
    memset(ids, 0, 512 * sizeof(SceUID));

    int count = 0;
    sceKernelGetModuleIdList(ids, 512, &count);

    int p;
    for (p = 0; p < count; p++)
    {
        SceModule *mod = sceKernelFindModuleByUID(ids[p]);
        if (mod)
        {
            if (strncmp(mod->modname, "USER_MAIN", 9) == 0)
            {
                return mod;
            }
        }
    }

    return NULL;
}