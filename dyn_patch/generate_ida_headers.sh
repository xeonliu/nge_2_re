#!/bin/bash
# 生成IDA Pro可用的PSP SDK头文件

set -e

echo "=== 第一步：使用psp-gcc预处理头文件 ==="

psp-gcc -E -P \
    -D_PSP_FW_VERSION=660 \
    -D"__attribute__(x)=" \
    -D"__extension__=" \
    -D"__inline__=" \
    -D"__inline=" \
    -D"inline=" \
    -D"static=" \
    -D"__asm__(x)=" \
    -D"__volatile__=" \
    -D"__restrict=" \
    -D"__restrict__=" \
    -D"nullptr=0" \
    -D"__builtin_va_list=void*" \
    -D"__typeof__(x)=int" \
    -I$PSPDEV/psp/sdk/include \
    allpsp.h \
    -o psp_signatures_raw.h

echo "预处理完成: psp_signatures_raw.h"

echo ""
echo "=== 第二步：清理不兼容的构造 ==="

python3 clean_ida_header.py

echo ""
echo "=== 生成完成! ==="
echo "IDA可用的头文件: psp_signatures_clean.h"
echo ""
echo "使用方法："
echo "1. 在IDA Pro中: File -> Load File -> Parse C Header File"
echo "2. 选择: psp_signatures_clean.h"
