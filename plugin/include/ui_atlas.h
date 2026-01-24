#ifndef __UI_ATLAS_H__
#define __UI_ATLAS_H__

#include <stdint.h>

// 初始化，将 atlas 数据加载到内存缓冲区
void uiInit(void);

// 核心：支持 UTF-8 的打印函数
void uiPrint(float x, float y, const char* str, uint32_t color);

#endif