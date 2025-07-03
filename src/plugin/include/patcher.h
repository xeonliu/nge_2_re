#pragma once
#include <stdint.h>

void patch();
void patch_function();
void patch_sentence();
int patch_from_external_file(const char* filename);