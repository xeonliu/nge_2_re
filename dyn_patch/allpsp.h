/* all_psp.h - 用于 IDA Pro 解析的总合头文件 */

// 1. 基础类型（包含 u32, u16 等）
#include <psptypes.h>

// 2. 内核基本类型
#include <pspkerneltypes.h>

// 3. 用户层核心模块 (user/*.h)
#include <psploadexec.h>
#include <psputils.h>
#include <pspthreadman.h>
#include <pspmodulemgr.h>
#include <pspiofilemgr.h>
#include <pspstdio.h>
#include <pspintrman.h>

// 4. 调试模块 (debug/*.h)
#include <pspdebug.h>

// 5. 其他常用模块（根据需要添加）
#include <pspdisplay.h>
#include <pspgu.h>
#include <pspctrl.h>

#include <psputility.h>

/* 如果你还有其他特定的 .h 文件，可以在此处继续添加 */