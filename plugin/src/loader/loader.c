#include <pspsdk.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <pspkernel.h>
#include <pspthreadman.h>
#include <pspmodulemgr.h>
#include <pspiofilemgr.h>

#include <pspgu.h>
#include <pspdisplay.h>

#include "patcher.h"

PSP_MODULE_INFO("EBOOT_LOADER", PSP_MODULE_USER, 1, 1);
PSP_NO_CREATE_MAIN_THREAD();

#define BUFFER_WIDTH 512
#define BUFFER_HEIGHT 272
#define SCREEN_WIDTH 480
#define SCREEN_HEIGHT BUFFER_HEIGHT

char list[0x20000] __attribute__((aligned(64)));

void initGu(){
    sceGuInit();

    //Set up buffers
    sceGuStart(GU_DIRECT, list);
    sceGuDrawBuffer(GU_PSM_8888,(void*)0,BUFFER_WIDTH);
    sceGuDispBuffer(SCREEN_WIDTH,SCREEN_HEIGHT,(void*)0x88000,BUFFER_WIDTH);
    sceGuDepthBuffer((void*)0x110000,BUFFER_WIDTH);

    //Set up viewport
    sceGuOffset(2048 - (SCREEN_WIDTH / 2), 2048 - (SCREEN_HEIGHT / 2));
    sceGuViewport(2048, 2048, SCREEN_WIDTH, SCREEN_HEIGHT);
    sceGuEnable(GU_SCISSOR_TEST);
    sceGuScissor(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

    //Set some stuff
    sceGuDepthRange(65535, 0); //Use the full buffer for depth testing - buffer is reversed order

    sceGuDepthFunc(GU_GEQUAL); //Depth buffer is reversed, so GEQUAL instead of LEQUAL
    sceGuEnable(GU_DEPTH_TEST); //Enable depth testing

    sceGuFinish();
    sceGuDisplay(GU_TRUE);
}

void endGu(){
    sceGuDisplay(GU_FALSE);
    sceGuTerm();
}

void startFrame(){
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFFFFFFFF); // White background
    sceGuClear(GU_COLOR_BUFFER_BIT);
}

void endFrame(){
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
    sceGuSwapBuffers();
}

typedef struct {
    unsigned short u, v;
    short x, y, z;
} Vertex;

void drawRect(float x, float y, float w, float h) {

    Vertex* vertices = (Vertex*)sceGuGetMemory(2 * sizeof(Vertex));

    vertices[0].x = x;
    vertices[0].y = y;

    vertices[1].x = x + w;
    vertices[1].y = y + h;

    sceGuColor(0xFF0000FF); // Red, colors are ABGR
    sceGuDrawArray(GU_SPRITES, GU_TEXTURE_16BIT | GU_VERTEX_16BIT | GU_TRANSFORM_2D, 2, 0, vertices);
}


#define PathOldBoot "disc0:/PSP_GAME/SYSDIR/BOOT.BIN"

static int main_thread(SceSize args, void *argp)
{

	initGu();
	startFrame();
	drawRect(100.0f, 100.0f, 280.0f, 72.0f);
	endFrame();
	sceKernelDelayThread(2000000); // 2 seconds
	endGu();

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