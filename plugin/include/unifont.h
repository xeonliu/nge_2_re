#pragma once

#include <stdint.h>

void unifont_init(void* buffer);
void unifont_print(float x, float y, const char* str, uint32_t color);