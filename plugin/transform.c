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

// UTF16 Encoding
const uint16_t* UTF16_TABLE = (uint16_t*)0x08a2fb60;

// lower bound of SJIS Encoding (u16) + Offset (u16)
const uint32_t *DAT_08a3325c = (uint32_t*)0x08a3325c;

// Input Space
// First Byte: 0xA1-0xF7
// Second Byte: 0xA1-0xFE
// 
// Output Space: 0xA600-0xDDFF
// index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1);
// mapped_code = 0xA600 + index;
extern uint16_t GB_2312[8192]; // GB2312 Encoding

uint16_t translate_code(uint16_t code) {
    if(code>=0xA600 && code<=0xDDFF) {
        return modified_to_utf16(code);
    }
    return sjis_to_utf16(code);
}

/** 
Use 0xA6-0xDD to store GB2312 Chinese Characters
*/
uint16_t modified_to_utf16(uint16_t code) {
    if(code>=0xc5f1) {
        // ERROR: Out of Range
    }
    return GB_2312[code-0xA600];
}

// FUN_08884680
uint16_t sjis_to_utf16(uint16_t sjis) {
    int low = 0;
    int high = 0x5a;
    int mid = low+high/2; // 0x2d

    int index;

    if(sjis==0x9480) {
        index = mid;
    } else {
        if(sjis<0x9480) {
            high = mid;
        } else {
            low = mid + 1;
        }
        index = binary_search(sjis, low, high);
    }

    // lower bound of SJIS Encoding (u16) + Offset to UTF16 Table (u16)
    uint16_t prefix = (DAT_08a2fb60[index] >> 16) & 0xFFFF;
    uint16_t offset = DAT_08a2fb60[index] & 0xFFFF;

    int table_offset = sjis-prefix+offset;
    return UTF16_TABLE[table_offset];
}

// FUN_08884724
// binary_search function
int binary_search(uint16_t target, int low, int high) {
    low = low & 0xFFFF;
    high = high & 0xFFFF;

    while (low <= high) {
        int mid = (low + high) >> 1;
        uint16_t mid_val = (DAT_08a2fb60[mid]>>16) & 0xFFFF;

        if (mid_val == target) {
            return mid;
        } else if (mid_val < target) {
            low = (mid + 1) & 0xFFFF;
        } else {
            high = (mid - 1) & 0xFFFF;
        }
    }

    return -1; // 如果未找到目标值，则返回 -1
}