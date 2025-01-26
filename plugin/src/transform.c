/**
Modify the SJIS Table to store more Chinese Characters
First Byte
0x00-0x7F: ASCII
0x81-0x9F: Hiragana, Katakana, Greek, Cyrillic, etc.
0xA1-0xDF: Half-width Katakana
0xE0-0xFC: Kanji

第二字节的范围是 0x40 - 0x7E 或 0x80 - 0xFC

Use 0xA6-0xDD to store more Chinese Characters
0xA600-0xDDFF.
*/
#include <pspkernel.h>

#include "transform.h"
#include "log.h"

// UTF16 Encoding
#define UTF16_TABLE_ADDRESS 0x08a2fb60

// lower bound of SJIS Encoding (u16) + Offset (u16)
// 0x20 0x00 0x00 0x00
// 0xa1 0x00 0x00 0x5f
// 0x40 0x81 0x9e 0x00
#define DAT_08a3325c_ADDRESS 0x08a3325c

// Input Space
// First Byte: 0xA1-0xF7
// Second Byte: 0xA1-0xFE
//
// Output Space: 0xA600-0xDDFF
// index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1);
// mapped_code = 0xA600 + index;
extern unsigned char GB_2312[16356];   // GB2312 Encoding
extern unsigned char SJIS_bin[360];    // SJIS Table
extern unsigned char UTF16_bin[14436]; // UTF16 Table
// Imported From Patcher.c
extern u32 offset_;

void init_transform()
{

    u16 *DAT_08a3325c = (u16 *)(SJIS_bin);
    u16 *UTF16_TABLE = (u16 *)(UTF16_bin);

    for (int i = 0; i < 10; ++i)
    {
        dbg_log("Code: %04x, Index: %04x", DAT_08a3325c[i << 1], DAT_08a3325c[(i << 1) + 1]);
    }

    dbg_log("Print DAT_08a3325c: %x\n", DAT_08a3325c);
    dbg_log("Print UTF16_TABLE: %x\n", UTF16_TABLE);
}

uint16_t translate_code(u16 code)
{

    u16 *DAT_08a3325c = (u16 *)(SJIS_bin);
    u16 *UTF16_TABLE = (u16 *)(UTF16_bin);
    if (code >= 0xA600 && code <= 0xDDFF)
    {
        return modified_to_utf16(code);
    }
    return sjis_to_utf16(code);
}

/**
Use 0xA6-0xDD to store GB2312 Chinese Characters
*/
uint16_t modified_to_utf16(u16 code)
{
    dbg_log("Modified to UTF16: %x\n", code);
    if (code >= 0xc5f1)
    {
        dbg_log("Out of Range: %x\n", code);
    }
    return ((u16 *)GB_2312)[code - 0xA600];
}

// FUN_08884680
uint16_t sjis_to_utf16(u16 sjis)
{

    u16 *DAT_08a3325c = (u16 *)(SJIS_bin);
    u16 *UTF16_TABLE = (u16 *)(UTF16_bin);
    dbg_log("SJIS to UTF16: %x\n", sjis);
    int low = 0;
    int high = 0x5a;
    int index;

    index = binary_search(sjis, low, high);

    // lower bound of SJIS Encoding (u16) + Offset to UTF16 Table (u16)
    uint16_t prefix = DAT_08a3325c[index << 1] & 0xFFFF;
    uint16_t offset = DAT_08a3325c[(index << 1) + 1] & 0xFFFF;

    int table_offset = sjis - prefix + offset;
    return UTF16_TABLE[table_offset];
}

// FUN_08884724
// binary_search function
int binary_search(uint16_t target, uint16_t low, uint16_t high)
{

    u16 *DAT_08a3325c = (u16 *)(SJIS_bin);
    u16 *UTF16_TABLE = (u16 *)(UTF16_bin);
    low = low & 0xFFFF;
    high = high & 0xFFFF;

    while (low <= high)
    {
        uint16_t mid = ((low + high) >> 1) & 0xFFFF;

        // 0x44 0x29 0x8b 0x8f
        uint16_t mid_val = DAT_08a3325c[mid << 1] & 0xFFFF;
        uint16_t next_val = DAT_08a3325c[(mid << 1) + 2] & 0xFFFF;

        if (target >= mid_val && (mid == high || target < next_val))
        {
            dbg_log("Found: %x\n", mid);
            return mid;
        }
        else if (mid_val < target)
        {
            low = (mid + 1) & 0xFFFF;
        }
        else
        {
            high = (mid - 1) & 0xFFFF;
        }
    }

    return -1; // 如果未找到目标值，则返回 -1
}