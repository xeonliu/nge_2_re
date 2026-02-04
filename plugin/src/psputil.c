#include "psputil.h"

// Patch for sceUtilitySavedataInitStart to set language to Chinese
int sceUtilitySavedataInitStartPatched(SceUtilitySavedataParam *params) {
    params->base.language = 11; // 设置语言为中文
    return sceUtilitySavedataInitStart(params);
}