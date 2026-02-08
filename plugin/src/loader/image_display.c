#include <pspgu.h>
#include <pspdisplay.h>
#include <pspiofilemgr.h>
#include <pspkernel.h>
#include <stdlib.h>
#include <string.h>
#include "image_display.h"

extern char list[0x20000];

typedef struct {
    unsigned short u, v;
    unsigned int color;
    short x, y, z;
} ImageVertex;

// Static buffer for image data (480x272 RGBA8888 = 522,240 bytes)
// Using aligned attribute for better performance
static unsigned int imageBuffer[480 * 272] __attribute__((aligned(16)));

/**
 * Load and display a raw RGBA8888 image from file.
 */
void displayImageFromFile(const char* filename, int width, int height, int duration_ms) {
    // Check if image fits in our static buffer
    if (width > 480 || height > 272) {
        return; // Image too large
    }
    
    // Clear buffer
    memset(imageBuffer, 0, sizeof(imageBuffer));
    
    // Read image file
    SceUID fd = sceIoOpen(filename, PSP_O_RDONLY, 0777);
    if (fd < 0) {
        return; // Failed to open file
    }
    
    int bytesToRead = width * height * sizeof(unsigned int);
    int bytesRead = sceIoRead(fd, imageBuffer, bytesToRead);
    sceIoClose(fd);
    
    if (bytesRead != bytesToRead) {
        return; // Failed to read complete image
    }

    // Flush data cache to ensure GE sees the updated buffer
    sceKernelDcacheWritebackInvalidateAll();
    
    // Need to use power-of-2 texture size (512x512 for safety)
    int texWidth = 512;
    int texHeight = 512;
    
    // Start rendering
    sceGuStart(GU_DIRECT, list);
    
    // Clear screen
    sceGuClearColor(0xFF000000);
    sceGuClear(GU_COLOR_BUFFER_BIT);
    
    // Enable texture
    sceGuEnable(GU_TEXTURE_2D);
    sceGuTexMode(GU_PSM_8888, 0, 0, 0);
    // Use the actual image width as the buffer stride
    sceGuTexImage(0, texWidth, texHeight, width, imageBuffer);
    sceGuTexFunc(GU_TFX_REPLACE, GU_TCC_RGBA);
    sceGuTexFilter(GU_LINEAR, GU_LINEAR);
    
    // Enable alpha blending
    sceGuEnable(GU_BLEND);
    sceGuBlendFunc(GU_ADD, GU_SRC_ALPHA, GU_ONE_MINUS_SRC_ALPHA, 0, 0);
    
    // Draw image as sprite
    ImageVertex* vertices = (ImageVertex*)sceGuGetMemory(2 * sizeof(ImageVertex));
    
    vertices[0].u = 0;
    vertices[0].v = 0;
    vertices[0].color = 0xFFFFFFFF;
    vertices[0].x = 0;
    vertices[0].y = 0;
    vertices[0].z = 0;
    
    vertices[1].u = width;
    vertices[1].v = height;
    vertices[1].color = 0xFFFFFFFF;
    vertices[1].x = width;
    vertices[1].y = height;
    vertices[1].z = 0;
    
    sceGuDrawArray(GU_SPRITES, GU_TEXTURE_16BIT | GU_COLOR_8888 | GU_VERTEX_16BIT | GU_TRANSFORM_2D, 
                   2, 0, vertices);
    
    // Disable blend and texture
    sceGuDisable(GU_BLEND);
    sceGuDisable(GU_TEXTURE_2D);
    
    // Finish rendering
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
    sceGuSwapBuffers();
    
    // Wait for specified duration
    if (duration_ms > 0) {
        sceKernelDelayThread(duration_ms * 1000); // Convert to microseconds
    }
}
