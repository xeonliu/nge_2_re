#pragma once

#include <stdint.h>

void font_init(uint8_t* hzk_ptr);

void draw_chinese_char(float x, float y, uint8_t high, uint8_t low, uint32_t color);

void psp_print(float x, float y, const char* str, uint32_t color);