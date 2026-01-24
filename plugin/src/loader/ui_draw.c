#include <pspgu.h>
#include <stdint.h>
#include "atlas_data.h"

extern unsigned char atlas_bin[];

// 初始化：直接使用 atlas_bin 作为纹理数据
void uiInit(void) {
    _atlas_vram_ptr = atlas_bin;
}

static uint32_t next_utf8_char(const char** s) {
    const unsigned char* p = (const unsigned char*)*s;
    uint32_t res = 0;
    if (p[0] < 0x80) { res = p[0]; *s += 1; }
    else if (p[0] < 0xE0) { res = ((p[0] & 0x1F) << 6) | (p[1] & 0x3F); *s += 2; }
    else if (p[0] < 0xF0) { res = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F); *s += 3; }
    else { *s += 1; res = '?'; }
    return res;
}

// 二分查找
static int get_char_info(uint32_t code, int* width) {
    int low = 0, high = ATLAS_CHAR_COUNT - 1;
    while (low <= high) {
        int mid = (low + high) / 2;
        if (atlas_index[mid].code == code) {
            *width = atlas_index[mid].width;
            return mid;
        }
        if (atlas_index[mid].code < code) low = mid + 1;
        else high = mid - 1;
    }
    return -1;
}

void uiPrint(float x, float y, const char* str, uint32_t color) {
    sceGuEnable(GU_TEXTURE_2D);
    sceGuTexMode(GU_PSM_8888, 0, 0, 0);
    sceGuTexImage(0, 256, 256, 256, _atlas_vram_ptr);
    sceGuTexFunc(GU_TFX_MODULATE, GU_TCC_RGBA); // 允许修改颜色
    sceGuTexFilter(GU_LINEAR, GU_LINEAR);     // TTF 贴图开启线性过滤更平滑
    
    // 启用 alpha 混合以支持透明背景
    sceGuEnable(GU_BLEND);
    sceGuBlendFunc(GU_ADD, GU_SRC_ALPHA, GU_ONE_MINUS_SRC_ALPHA, 0, 0);

    const char* p = str;
    float cur_x = x;
    
    while (*p) {
        // UTF-8 解码逻辑 (同前)
        uint32_t code = next_utf8_char(&p); 
        int char_w = 0;
        int idx = get_char_info(code, &char_w);
        
        if (idx >= 0) {
            int u = (idx % 16) * 16;
            int v = (idx / 16) * 16;

            struct { float u,v; uint32_t c; float x,y,z; } *verts;
            verts = (void*)sceGuGetMemory(2 * 24);
            
            verts[0].u = u;    verts[0].v = v;    verts[0].c = color;
            verts[0].x = cur_x; verts[0].y = y;    verts[0].z = 0;
            
            verts[1].u = u+16; verts[1].v = v+16; verts[1].c = color;
            verts[1].x = cur_x+16; verts[1].y = y+16; verts[1].z = 0;

            sceGuDrawArray(GU_SPRITES, GU_TEXTURE_32BITF|GU_COLOR_8888|GU_VERTEX_32BITF|GU_TRANSFORM_2D, 2, 0, verts);
            
            cur_x += char_w + 1; // 使用 TTF 真实宽度进行步进
        }
    }
    
    // 恢复状态
    sceGuDisable(GU_BLEND);
}