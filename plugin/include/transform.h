#pragma once
#include <stdint.h>

uint16_t translate_code(uint16_t code);
uint16_t modified_to_utf16(uint16_t code);

// Reversed from Binary.
// FUN_08884680
uint16_t sjis_to_utf16(uint16_t sjis);
// FUN_08884724
int binary_search(uint16_t sjis, uint16_t low, uint16_t high);
