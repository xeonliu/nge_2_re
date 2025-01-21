# 《新世纪福音战士 2 ：被创造的世界》汉化计划

本仓库 Fork 自 [rezual/nge_2_re](https://github.com/rezual/nge_2_re/)，参见[原项目在`forum.evageeks.org`上的帖子](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

本仓库在原项目基础上添加了一些目录，它们是：

- `zh_cn`
  - `crowdin`：用于处理从 Crowdin 平台上传和下载的文本。
  - `elf_patch`：用于将码表和翻译覆盖到 EBOOT.BIN中
  - `encoding`：用于提取 EBOOT.BIN 内嵌的码表，依据词频生成新的码表，并对码表实施替换

本仓库**中文翻译文本**按照[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)开源协议共享。

本仓库日文原文与英文翻译文本版权由原作者所有。

# 项目进度&贡献指南
见 [Paratranz](https://paratranz.cn/projects/10882)

## TODO
+ [ ] 使用数据库储存解析后的内容
+ [ ] 一键导出待翻译文本
+ [ ] 从Paratranz导入翻译文本
+ [ ] 搭建实时翻译客户端
+ [ ] 引入大模型（如Sakura）进行翻译
+ [ ] 建立待翻译图片仓库
+ [ ] 建立完整项目结构，能够一键Patch。
+ [ ] 引入CI/CD，能够自动生成Patch应用
+ [ ] 搭建翻译计划网站
+ [x] 对宣发网站存档。

# 解密EBOOT.BIN
1. 打开PPSSPP
2. `设置`->`工具`->`开发者工具`->`载入游戏时保存已解密的EBOOT.bin`
3. 重新进入游戏
4. 提示框会显示解密`EBOOT.bin`保存的地址

# Ghidra
+ [ghidra-allegrex](https://github.com/kotcrab/ghidra-allegrex)

# 文字加载

`0x8874180`

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

`0x649c0`：校验SJIS

`0x8884680`：二分查找查表函数
```C
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


0x8873f14

```C

void FUN_08873f14(int param_1,ushort param_2)

{
  short sVar1;
  ushort uVar2;
  undefined2 uVar3;
  int iVar4;
  undefined4 uVar5;
  short *psVar6;
  short sVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  
  iVar8 = *(int *)(param_1 + 0xe4);
  iVar4 = FUN_08868718(*(undefined4 *)(iVar8 + 0x20));
  
  if (iVar4 == 0) {
    iVar4 = *(int *)(iVar8 + 0x20);
LAB_08873f6c:
    uVar9 = (uint)*(byte *)(*(int *)(iVar4 + 0x20) + 6);
  }
  else {
    iVar4 = *(int *)(iVar8 + 0x20);
    if ((*(byte *)(*(int *)(iVar4 + 0x20) + 5) >> 1 & 1) == 0) goto LAB_08873f6c;
    if (param_2 == 0x20) {
      uVar10 = FUN_08868718(iVar4,0x20,0);
      uVar9 = FUN_08873570(uVar10,0);
    }
    else {
      // SJIS转换
      uVar10 = FUN_08867ef0(iVar4,param_2);
      uVar5 = FUN_08868718(*(undefined4 *)(iVar8 + 0x20));
      uVar9 = FUN_08873570(uVar5,uVar10);
      FUN_088686e8(*(undefined4 *)(iVar8 + 0x20),uVar10);
    }
  }
  
  if ((0xff >= param_2) && (*(char *)(*(int *)(*(int *)(iVar8 + 0x20) + 0x20) + 4) == '\0')) {
    uVar9 = (int)uVar9 / 2;
  }
  
  if ((int)((int)*(short *)(*(int *)(param_1 + 0xe4) + 4) *
           (uint)*(byte *)(*(int *)(*(int *)(*(int *)(param_1 + 0xe4) + 0x20) + 0x20) + 6)) <
      (int)((int)*(short *)(iVar8 + 8) + uVar9)) {
    FUN_08874648(param_1);
  }
  
  sVar1 = (short)uVar9;
  
  if (param_2 == 0xa0) {
    if (*(short *)(iVar8 + 0x1e) == 0) {
      trap(7);
    }
    iVar4 = (int)*(short *)(iVar8 + 10) / (int)*(short *)(iVar8 + 0x1e);
    if (*(int *)(iVar8 + 0x3c) <= iVar4) {
      sVar7 = *(short *)(iVar8 + 8);
      goto LAB_08874098;
    }
    psVar6 = (short *)(iVar4 * 2 + *(int *)(iVar8 + 0x38));
    *psVar6 = *psVar6 + sVar1;
  }
  else {
    uVar2 = 0x20;
    if (0xa0 < param_2) {
      uVar2 = 0x8140;
    }
    sVar7 = *(short *)(iVar8 + 8);
    
    if (param_2 == uVar2) goto LAB_08874098;
    
    iVar4 = iVar8 + *(short *)(iVar8 + 0x1a) * 0x10;
    *(short *)(iVar4 + 0x40) = sVar7;
    *(undefined2 *)(iVar4 + 0x42) = *(undefined2 *)(iVar8 + 10);
    
    if (0xff < param_2) {
      // 双字节
      *(undefined *)(iVar4 + 0x46) = 0;
    }
    else if (*(char *)(*(int *)(*(int *)(iVar8 + 0x20) + 0x20) + 4) == '\0') {
      *(undefined *)(iVar4 + 0x46) = 1;
    }
    else {
      *(undefined *)(iVar4 + 0x46) = 0;
    }
    // SJIS转换
    uVar3 = FUN_08867ef0(*(undefined4 *)(iVar8 + 0x20),param_2,0);
    *(undefined2 *)(iVar4 + 0x44) = uVar3;
    uVar10 = *(undefined4 *)(iVar8 + 0x14);
    *(undefined *)(iVar4 + 0x47) = 0;
    *(undefined4 *)(iVar4 + 0x48) = uVar10;
    if (*(short *)(iVar8 + 0x1e) == 0) {
      trap(7);
    }
    iVar4 = (int)*(short *)(iVar8 + 10) / (int)*(short *)(iVar8 + 0x1e);
    if (iVar4 < *(int *)(iVar8 + 0x3c)) {
      psVar6 = (short *)(iVar4 * 2 + *(int *)(iVar8 + 0x38));
      *psVar6 = *psVar6 + sVar1;
      sVar7 = *(short *)(iVar8 + 0x1a);
    }
    else {
      sVar7 = *(short *)(iVar8 + 0x1a);
    }
    *(short *)(iVar8 + 0x1a) = sVar7 + 1;
  }
  sVar7 = *(short *)(iVar8 + 8);
LAB_08874098:
  *(short *)(iVar8 + 8) = sVar7 + sVar1;
  return;
}


```