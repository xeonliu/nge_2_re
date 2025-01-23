#include <pspkernel.h>

#include "log.h"
#include "patcher.h"
#include "transform.h"

#define CODE_JAL 0x0C000000
#define CODE_JMsk 0x03FFFFFF

#define COND_INST_OPERAND_ADDR 0x08874260
// 088691b8 a0 11 22 0e     jal FUN_08884680
#define JAL_INST_ADDR 0x088691b8

#define STD_BASE 0x08804000
u32 game_base;

void patch(SceUID mid_boot)
{
    SceKernelModuleInfo info;
    info.size = sizeof(info);
    if (sceKernelQueryModuleInfo(mid_boot, &info))
    {
        LOG("Got module info failed.");
    }
    game_base = info.segmentaddr[0];

    LOG("mod_base = 0x%08X\n", game_base);

    patch_function();
    patch_sentence();
};

void patch_function()
{
    // Patch Code in FUN_08874180
    /**
     * if ((0x7f < uVar2) && ((uVar2 < 0xa0 || (0xdf < uVar2)))) {
          // Read the next byte
          bVar1 = *pbVar3;
          // Skip 2 bytes
          pbVar3 = param_2 + 2;
          // Now uVar2 is a 2 byte value
          uVar2 = (uint)bVar1 | uVar2 << 8;
        }

        Extend The Range uVar2 >= 0xa6 so that First Byte Range in [a6,de) Will Also Be Considered as two byte characters.
        Change Bytes at 0x8874260 to a600a62c
    */
    u32 addrAdjust = game_base - STD_BASE;

    *(uint8_t *)(COND_INST_OPERAND_ADDR + addrAdjust) = 0xa6;
    sceKernelDcacheWritebackInvalidateRange((void *)COND_INST_OPERAND_ADDR + addrAdjust, 1);
    sceKernelIcacheInvalidateRange((void *)COND_INST_OPERAND_ADDR + addrAdjust, 1);

    /* Hook The Funtion Calls */

    // Generate the JAL Instruction
    uint32_t target_addr = (uint32_t)&translate_code;
    // jal 0x80680
    // 0x0C000000 | (0x80680 >> 2)
    // 0x0C000000 | 0x0201A0
    // 指令：0x0C0201A0
    // 以小端储存
    uint32_t jal_inst = CODE_JAL | (CODE_JMsk & (target_addr >> 2));
    // Patch The JAL Instruction
    LOG("Instruction: 0x%08X\n", jal_inst);
    // The Original Code is for converting Non-ASCII SJIS Characters to UTF16
    // Now we extend the range to include More Chinese Characters
    *(uint32_t *)(JAL_INST_ADDR + addrAdjust) = jal_inst;
    LOG("position: 0x%08X\n", JAL_INST_ADDR + addrAdjust);
    sceKernelDcacheWritebackInvalidateRange((void *)(JAL_INST_ADDR + addrAdjust), 4);
    sceKernelIcacheInvalidateRange((void *)(JAL_INST_ADDR + addrAdjust), 4);
}

void patch_sentence()
{
    void *address = (void *)(0x089B5880 + game_base - STD_BASE);
    // SJIS Sentece中字符均是大端
    uint8_t *shinji = (uint8_t *)address;
    shinji[0] = 0x89;
    shinji[1] = 0x01;

    sceKernelDcacheWritebackInvalidateRange(address, 4);
    sceKernelIcacheInvalidateRange(address, 4);
};