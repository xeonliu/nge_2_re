#include <pspkernel.h>

#include "patcher.h"
extern "C"
{
#include "transform.h"

    void _exit(int status)
    {
        sceKernelExitThread(status);
    }

    void *__dso_handle = 0;
}

#define CODE_JAL 0x0C000000

#define COND_INST_OPERAND_ADDR 0x08874260
// 088691b8 a0 11 22 0e     jal FUN_08884680
#define JAL_INST_ADDR 0x088691b8

Patcher *Patcher::get_instance()
{
    static Patcher instance;
    return &instance;
}

Patcher::Patcher() : logger_(Logger::get_instance())
{
    logger_->log("Patcher Constructor");
}

void Patcher::patch()
{
    patch_function();
    patch_sentence();
};

void Patcher::patch_function()
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
    *(uint8_t *)(COND_INST_OPERAND_ADDR) = 0xa6;
    sceKernelDcacheWritebackInvalidateRange((void *)COND_INST_OPERAND_ADDR, 1);
    sceKernelIcacheInvalidateRange((void *)COND_INST_OPERAND_ADDR, 1);

    /* Hook The Funtion Calls */

    // Generate the JAL Instruction
    uint32_t target_addr = (uint32_t)&translate_code;
    // jal 0x80680
    // 0x0C000000 | (0x80680 >> 2)
    // 0x0C000000 | 0x0201A0
    // 指令：0x0C0201A0
    // 以小端储存
    uint32_t jal_inst = CODE_JAL | (target_addr >> 2);
    // Patch The JAL Instruction
    // The Original Code is for converting Non-ASCII SJIS Characters to UTF16
    // Now we extend the range to include More Chinese Characters
    *(uint32_t *)JAL_INST_ADDR = jal_inst;
    sceKernelDcacheWritebackInvalidateRange((void *)JAL_INST_ADDR, 4);
    sceKernelIcacheInvalidateRange((void *)JAL_INST_ADDR, 4);

    logger_->log("Patched JAL INST");
}

void Patcher::patch_sentence()
{
    void *address = (void *)(0x089B5880);
    // SJIS Sentece中字符均是大端
    uint8_t *shinji = (uint8_t *)address;
    shinji[0] = 0x89;
    shinji[1] = 0x01;

    sceKernelDcacheWritebackInvalidateRange(address, 4);
    sceKernelIcacheInvalidateRange(address, 4);
};