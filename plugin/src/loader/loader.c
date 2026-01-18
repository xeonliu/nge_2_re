#include <pspsdk.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <pspkernel.h>
#include <pspthreadman.h>
#include <pspmodulemgr.h>
#include <pspiofilemgr.h>

#include "patcher.h"

PSP_MODULE_INFO("EBOOT_LOADER", PSP_MODULE_USER, 1, 1);
PSP_NO_CREATE_MAIN_THREAD();

#define PathOldBoot "disc0:/PSP_GAME/SYSDIR/BOOT.BIN"

static int main_thread(SceSize args, void *argp)
{

	SceUID eboot_mid = sceKernelLoadModule(PathOldBoot, 0, NULL);
	if (eboot_mid >= 0)
	{
		sceKernelStartModule(eboot_mid, 0, NULL, NULL, NULL);
	}

	sceKernelDelayThread(1000);
	
	// USER_MAIN Thread Will Only Last for a fraction of second.
	SceKernelModuleInfo info;
	sceKernelQueryModuleInfo(eboot_mid, &info);
	u32 base_addr = info.segmentaddr[0];

	patch(base_addr);

	// TODO: 驻留内存，提供外挂功能

	return sceKernelExitDeleteThread(0);
}

int module_start(SceSize args, void *argp)
{
	// TODO: Add Welcome Page
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