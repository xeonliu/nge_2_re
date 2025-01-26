# EBOOT Loader
Load the game and patch it.
+ Replace the orginal `EBOOT.BIN` with this one.
+ Decrypt `EBOOT.BIN` and rename it to `BOOT.BIN`

> You can decrypt `EBOOT.BIN` using `PPSSPP`

> 1. 打开PPSSPP
> 2. `设置`->`工具`->`开发者工具`->`载入游戏时保存已解密的EBOOT.bin`
> 3. 进入游戏
> 4. 提示框会显示解密`EBOOT.bin`保存的地址

# Build Instruction

+ Generate EBOOT.BIN
```sh
make release
```

+ Generate EBOOT.BIN with Debug Log
```sh
make debug
```

# Contributing

```
├── include
├── scripts # Contains scripts to Generate Coding Table & SJIS/UTF16 Table Binaries extracted from the Game
└── src
    ├── bin # Binarires in `scripts` converted to C array
    ├── loader # EBOOT Loader
    ├── plugin # Unused
    └── utils # Log Util
```

+ `patcher.c` Patches a condition check and a jal call
+ `transform.c` Contains the patched function

## Condition Patch

Decompiled Using [ghidra-allegrex](https://github.com/kotcrab/ghidra-allegrex).

```C
void FUN_08874180(undefined4 param_1,byte *param_2)
{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  // Current Byte
  uVar2 = (uint)*param_2;
  do {
    // Next Byte
    pbVar3 = param_2 + 1;
    switch(uVar2) {
    case 0:
      return;
    default:
      if (uVar2 < 0x20) {
        // Current Byte
        uVar2 = (uint)*pbVar3;
        // Update Next Pos
        param_2 = pbVar3;
      }
      else {
        // 去除了半角片假名
        // NOTE: Patch HERE!
        // ((0x7f < uVar2) && ((uVar2 < 0xa0 || (0xa6 <= uVar2))))
        if ((0x7f < uVar2) && ((uVar2 < 0xa0 || (0xdf < uVar2)))) {
          // Read the next byte
          bVar1 = *pbVar3;
          // Skip 2 bytes
          pbVar3 = param_2 + 2;
          // Now uVar2 is a 2 byte value
          uVar2 = (uint)bVar1 | uVar2 << 8;
        }
        // Param1 可能是一个指向Struct的指针
        FUN_08873f14(param_1,uVar2);
        // Update Curr Byte
        uVar2 = (uint)*pbVar3;
        // Update Next Pos
        param_2 = pbVar3;
      }
      break;
    case 10:
      FUN_08874648(param_1);
      // 修改结构体
      /**
      void FUN_08874648(int param_1)
      {
        int iVar1;
        
        iVar1 = *(int *)(param_1 + 0xe4);
        *(undefined2 *)(iVar1 + 8) = 0;
        *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + *(short *)(iVar1 + 0x1e);
        return;
      }
      **/
      // Read Next Byte into uVar2
      uVar2 = (uint)*pbVar3;
      // Update Next Pos
      param_2 = pbVar3;
      break;
    case 0x10:
      FUN_08874664(param_1);

      uVar2 = (uint)*pbVar3;
      param_2 = pbVar3;
      break;
    case 0x14:
      // Next Byte
      pbVar3 = (byte *)FUN_0881204c(*pbVar3);
      /*
      int FUN_0881204c(int param_1)
      {
        return param_1 * 4 + 0x89ea208;
      }
      */
      // 返回了一个地址
      // 在该地址取出u32
      FUN_08874944(param_1,(uint)pbVar3[3] << 0x18 | (uint)pbVar3[2] << 0x10 | (uint)pbVar3[1] << 8
                           | (uint)*pbVar3);
      // 使用该u32修改了param_1内部数据
      /**
      void FUN_08874944(int param_1,u32 param_2)
      {
        *(u32 *)(*(int *)(param_1 + 0xe4) + 0x14) = param_2;
        return;
      }
      */
      uVar2 = (uint)param_2[2];
      param_2 = param_2 + 2;
      break;
    case 0x16:
      // 取出next_byte
      FUN_08873d5c(param_1,*pbVar3);
      // 取出next next byte
      uVar2 = (uint)param_2[2];
      // param_2跳过两个
      param_2 = param_2 + 2;
    }
  } while( true );
}
```

## SJIS Conversion
```C
// uint16_t sjis_to_utf16(u16 sjis)
undefined2 FUN_08884680(uint param_1)
{
  undefined4 uVar1;
  undefined4 uVar2;
  uint uVar3;
  
  param_1 = param_1 & 0xffff;
  uVar1 = 0;
  uVar2 = 0x2d;
  if (DAT_08a33310 <= param_1) {
    uVar1 = 0x2e;
    uVar2 = 0x5a;
    if (param_1 <= DAT_08a33310) {
      uVar3 = 0x2d;
      goto LAB_088846d0;
    }
  }
  uVar3 = FUN_08884724(param_1,uVar1,uVar2);
  uVar3 = uVar3 & 0xffff;
LAB_088846d0:
  return *(undefined2 *)
          (&DAT_08a2fb60 +
          ((param_1 - *(ushort *)(&DAT_08a3325c + uVar3 * 4)) +
          (uint)*(ushort *)(&DAT_08a3325e + uVar3 * 4)) * 2);
}
```