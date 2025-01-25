#include <pspsdk.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <pspkernel.h>
#include <pspthreadman.h>
#include <pspmodulemgr.h>
#include <pspiofilemgr.h>

PSP_MODULE_INFO("EBOOT_LOADER", PSP_MODULE_USER, 1, 0);
PSP_NO_CREATE_MAIN_THREAD();

#define PathOldBoot "disc0:/PSP_GAME/SYSDIR/BOOT.BIN"
#define PathPrx "ms0:/PSP/patch.prx"

#define LOG_FILE "ms0:/PSP/loader_log.txt"
void *_exit = 0;

void dbg_log(const char *format, ...)
{
	SceUID f = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);
	if (f >= 0)
	{
		va_list args;
		va_start(args, format);

		char buffer[256];
		vsnprintf(buffer, sizeof(buffer), format, args);
		sceIoWrite(f, buffer, strlen(buffer));

		va_end(args);
		sceIoClose(f);
	}
}

SceModule *pspModuleLoadStartInKernelPart(const char *modpath, void *argp)
{
	SceKernelLMOption option = {
		.size = sizeof(SceKernelLMOption),
		.mpidtext = (SceUID)1, // SceUID mpid = 1 Kernel Partition
		.mpiddata = (SceUID)1,
		.position = 0,
		.access = 1,
	};

	SceUID modid = sceKernelLoadModule(modpath, 0, &option);
	if (modid < 0)
	{
		dbg_log("sceKernelLoadModule(%s) failed with : %x\n", modpath, modid);
		return NULL;
	}

	int status = 0;
	int res = sceKernelStartModule(modid, 0, argp, &status, NULL);
	(void)status;

	if (res < 0)
	{
		dbg_log("sceKernelStartModule(%s) failed with : %x\n", modpath, res);
		sceKernelUnloadModule(modid);
		return NULL;
	}

	return sceKernelFindModuleByUID(modid);
}

static void pspForEachLoadedModule(void (*callback)(SceModule *))
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
			callback(mod);
		}
	}
}

void print_module(SceModule *mod)
{
	if (!mod)
	{
		return;
	}

	if (strncmp(mod->modname, "sce", 3) != 0)
	{
		dbg_log("Module Name: %s\n", mod->modname);
		dbg_log("Module UID: %x\n", mod->modid);
		dbg_log("Module Start: %x\n", mod->text_addr);
		dbg_log("Module End: %x\n", mod->text_addr + mod->text_size);
		dbg_log("Entry Addr: %x\n", mod->entry_addr);

		SceKernelModuleInfo info;
		sceKernelQueryModuleInfo(mod->modid, &info);
		// This Seems to be the real Base Address in PPSSPP
		dbg_log("Base In Module Info: %x\n", info.segmentaddr[0]);
	}
}

static int main_thread(SceSize args, void *argp)
{

	pspSdkInstallNoDeviceCheckPatch();
	pspSdkInstallNoPlainModuleCheckPatch();
	pspSdkInstallKernelLoadModulePatch();

	SceUID eboot_mid = sceKernelLoadModule(PathOldBoot, 0, NULL);
	if (eboot_mid >= 0)
	{
		sceKernelStartModule(eboot_mid, 0, NULL, NULL, NULL);
		dbg_log("EBOOT.BIN loaded\n");
	}

	// USER_MAIN Thread Will Only Last for a fraction of second.
	SceKernelModuleInfo info;
	sceKernelQueryModuleInfo(eboot_mid, &info);
	u32 base_addr = info.segmentaddr[0];
	dbg_log("EBOOT.BIN Base Address: %x\n", base_addr);
	SceModule *prx_module = pspModuleLoadStartInKernelPart(PathPrx, (void *)base_addr);
	if (prx_module)
	{
		dbg_log("patch.prx loaded\n");
	}
	else
	{
		dbg_log("patch.prx failed to load\n");
	}

	pspForEachLoadedModule(print_module);

	return sceKernelExitDeleteThread(0);
}

int module_start(SceSize args, void *argp)
{
	int th = sceKernelCreateThread("loader", main_thread, 0x1F, 0x1000, 0, 0);
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