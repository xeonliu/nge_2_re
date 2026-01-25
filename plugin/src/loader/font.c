#include "font.h"

static unsigned char* _hzk_data = NULL;

void fontInit(unsigned char* hzk_ptr) {
    _hzk_data = hzk_ptr;
}

// 将 1-bit 点阵转换为 32-bit ABGR 纹理
// PSP 的 8888 格式在内存中其实是 R,G,B,A 字节序
static void fill_char_buffer(uint32_t* dest, unsigned char* font_data, uint32_t color) {
    uint32_t alpha_mask = color & 0xFF000000;
    uint32_t rgb_mask = color & 0x00FFFFFF;

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 2; j++) {
            unsigned char row = font_data[i * 2 + j];
            for (int bit = 0; bit < 8; bit++) {
                // 如果点阵位为 1，设为指定颜色；为 0 则设为全透明
                if (row & (0x80 >> bit)) {
                    dest[i * 16 + (j * 8 + bit)] = color;
                } else {
                    dest[i * 16 + (j * 8 + bit)] = 0x00000000; // 透明
                }
            }
        }
    }
}

void drawChineseChar(float x, float y, unsigned char high, unsigned char low, uint32_t color) {
    if (!_hzk_data) return;

    // 计算 HZK16 偏移量
    int offset = ((high - 0xA1) * 94 + (low - 0xA1)) * 32;
    unsigned char* data = _hzk_data + offset;

    // 分配显存空间用于存放 16x16 的纹理 (16*16*4 字节)
    uint32_t* tex_buffer = (uint32_t*)sceGuGetMemory(16 * 16 * 4);
    fill_char_buffer(tex_buffer, data, color);

    // 设置纹理状态
    sceGuEnable(GU_TEXTURE_2D);
    sceGuTexMode(GU_PSM_8888, 0, 0, 0);
    sceGuTexImage(0, 16, 16, 16, tex_buffer);
    sceGuTexFunc(GU_TFX_REPLACE, GU_TCC_RGBA);
    sceGuTexFilter(GU_NEAREST, GU_NEAREST); // 点阵字不需要平滑

    // 绘制
    typedef struct {
        unsigned short u, v;
        short x, y, z;
    } Vert;

    Vert* vertices = (Vert*)sceGuGetMemory(2 * sizeof(Vert));
    vertices[0].u = 0;  vertices[0].v = 0;
    vertices[0].x = x;  vertices[0].y = y; vertices[0].z = 0;
    vertices[1].u = 16; vertices[1].v = 16;
    vertices[1].x = x + 16; vertices[1].y = y + 16; vertices[1].z = 0;

    sceGuDrawArray(GU_SPRITES, GU_TEXTURE_16BIT | GU_VERTEX_16BIT | GU_TRANSFORM_2D, 2, 0, vertices);
    sceGuDisable(GU_TEXTURE_2D);
}

void pspPrint(float x, float y, const char* str, uint32_t color) {
    float cur_x = x;
    while (*str) {
        if ((unsigned char)*str >= 0xA1) {
            drawChineseChar(cur_x, y, str[0], str[1], color);
            str += 2;
            cur_x += 16;
        } else {
            // 这里可以添加 drawAsciiChar，或者简单跳过空格
            if (*str == ' ') cur_x += 8;
            str++;
        }
    }
}