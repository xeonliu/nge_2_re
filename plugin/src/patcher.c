#include <pspsdk.h>
#include <pspkernel.h>
#include "patcher.h"
#include "transform.h"
#include "log.h"

#define MIPS_J_ADDRESS(x) (((u32)((x)) & 0x3fffffff) >> 2)

#define NOP 0x000C0000
#define JAL_TO(x) (0x0E000000 | MIPS_J_ADDRESS(x))
#define J_TO(x) (0x08000000 | MIPS_J_ADDRESS(x))
#define LUI(x, y) (0x3C000000 | ((x & 0x1f) << 0x10) | (y & 0xffff))

// Codes to Patch
#define COND_INST_OPERAND_ADDR 0x08874260
// 088691b8 a0 11 22 0e     jal FUN_08884680
#define JAL_INST_ADDR 0x088691b8

// The Default Load Position for USER_MAIN Module.
// The Addresses above is based on this address.
#define STD_BASE 0x08804000

u32 offset_;

void patch(u32 mod_base)
{
    offset_ = mod_base - 0x08804000;
    init_transform();
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
    {
        // Dump the Original Code
        u32 code_pos = COND_INST_OPERAND_ADDR + offset_;
        dbg_log("Original Code at %x\n", code_pos);
        dbg_log("Original Code: %x\n", *(uint32_t *)code_pos);

        // Patch The Code
        u32 state = pspSdkDisableInterrupts();
        { // SJIS Sentece中字符均是大端
            _sb(0xa6, (u32)code_pos);
            sceKernelDcacheWritebackAll();
            sceKernelIcacheInvalidateAll();
        }
        pspSdkEnableInterrupts(state);

        // Dump the Patched Code
        dbg_log("Patched Code at %x\n", code_pos);
        dbg_log("Patched Code: %x\n", *(uint32_t *)code_pos);
    }

    /* Hook The Funtion Calls */
    // Generate the JAL Instruction
    {
        // Dump the Original Code
        u32 code_pos = JAL_INST_ADDR + offset_;

        dbg_log("Original Code at %x\n", code_pos);
        dbg_log("Original Code: %x\n", *(uint32_t *)code_pos);

        // Patch The JAL Instruction
        // The Original Code is for converting Non-ASCII SJIS Characters to UTF16
        // Now we extend the range to include More Chinese Characters
        uint32_t jal_inst = JAL_TO(translate_code);
        u32 state = pspSdkDisableInterrupts();
        {
            _sw(jal_inst, (u32)code_pos);
            sceKernelDcacheWritebackAll();
            sceKernelIcacheInvalidateAll();
        }
        pspSdkEnableInterrupts(state);

        // Dump the Patched Code
        dbg_log("Patched Code at %x\n", code_pos);
        dbg_log("Patched Code: %x\n", *(uint32_t *)code_pos);
    }
}

void patch_sentence()
{
    // SJIS Sentece中字符均是大端
    void *address = (void *)(0x089B5880) + offset_;
    dbg_log("Address: %x\n", address);
    dbg_log("Content: %x\n", *(u32 *)address);

    u32 state = pspSdkDisableInterrupts();
    { // SJIS Sentece中字符均是大端
        // 0x8940 0x8941
        _sw(0x41894089, (u32)address);
        sceKernelDcacheWritebackAll();
        sceKernelIcacheInvalidateAll();
    }
    pspSdkEnableInterrupts(state);

    dbg_log("Content: %x\n", *(u32 *)address);
};