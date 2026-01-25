#include "unifont.h"

#include <pspgu.h>

extern unsigned char unifont_bin[];

// 简单的 UTF-8 解码器
static uint32_t utf8_to_unicode(const char** s) {
    const unsigned char* p = (const unsigned char*)*s;
    uint32_t res = 0;
    if (p[0] < 0x80) { res = p[0]; *s += 1; }
    else if (p[0] < 0xE0) { res = ((p[0] & 0x1F) << 6) | (p[1] & 0x3F); *s += 2; }
    else if (p[0] < 0xF0) { res = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); *s += 3; }
    return res;
}

void drawGlyph(float x, float y, uint32_t code, uint32_t color) {
    if (!unifont_bin || code > 0xFFFF) return;

    uint8_t* data = unifont_bin + (code * 32);
    
    // 判断是 8x16 还是 16x16：检查后 16 字节是否全为 0
    int is_narrow = 1;
    for (int i = 16; i < 32; i++) {
        if (data[i] != 0) {
            is_narrow = 0;
            break;
        }
    }
    
    uint32_t* tex = (uint32_t*)sceGuGetMemory(16 * 16 * 4);
    for (int i = 0; i < 16; i++) {
        uint16_t row;
        if (is_narrow) {
            // 8x16: 每行 1 字节，数据在高 8 位
            row = data[i] << 8;
        } else {
            // 16x16: 每行 2 字节
            row = (data[i*2] << 8) | data[i*2+1];
        }
        for (int b = 0; b < 16; b++) {
            tex[i * 16 + b] = (row & (0x8000 >> b)) ? color : 0x00000000;
        }
    }

    sceGuEnable(GU_TEXTURE_2D);
    sceGuTexMode(GU_PSM_8888, 0, 0, 0);
    sceGuTexImage(0, 16, 16, 16, tex);
    sceGuTexFunc(GU_TFX_REPLACE, GU_TCC_RGBA);
    sceGuTexFilter(GU_NEAREST, GU_NEAREST);
    
    // 启用 alpha 混合来正确处理透明度
    sceGuEnable(GU_BLEND);
    sceGuBlendFunc(GU_ADD, GU_SRC_ALPHA, GU_ONE_MINUS_SRC_ALPHA, 0, 0);

    struct { unsigned short u, v; short x, y, z; } *verts;
    verts = (void*)sceGuGetMemory(2 * 10);
    verts[0].u = 0;  verts[0].v = 0;  verts[0].x = x;      verts[0].y = y;      verts[0].z = 0;
    verts[1].u = 16; verts[1].v = 16; verts[1].x = x + 16; verts[1].y = y + 16; verts[1].z = 0;

    sceGuDrawArray(GU_SPRITES, GU_TEXTURE_16BIT | GU_VERTEX_16BIT | GU_TRANSFORM_2D, 2, 0, verts);
    
    sceGuDisable(GU_BLEND);
    sceGuDisable(GU_TEXTURE_2D);
}

void unifont_print(float x, float y, const char* str, uint32_t color) {
    const char* p = str;
    float cur_x = x;
    while (*p) {
        uint32_t code = utf8_to_unicode(&p);
        drawGlyph(cur_x, y, code, color);
        
        // 简单的宽度判定：ASCII 是半角
        cur_x += (code < 128) ? 8 : 16;
    }
}