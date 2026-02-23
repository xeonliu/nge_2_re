#!/usr/bin/env python3
"""清理PSP头文件使其兼容IDA Pro"""

import re

def clean_psp_header(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    cleaned_lines = []
    in_inline_function = False
    brace_count = 0
    
    for i, line in enumerate(lines, 1):
        # 跳过 __typeof__ 定义
        if '__typeof__' in line:
            cleaned_lines.append(f'// {line}')  # 注释掉而不是删除
            continue
        
        # 检测 __inline 函数开始
        if '__inline' in line and not in_inline_function:
            in_inline_function = True
            brace_count = 0
            continue
        
        # 如果在 inline 函数内部，跟踪大括号
        if in_inline_function:
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            # 函数结束
            if brace_count == 0 and '}' in line:
                in_inline_function = False
            continue
        
        # 移除 restrict 关键字 (IDA不支持)
        line = re.sub(r'\brestrict\b', '', line)
        
        # 保留其他所有行
        cleaned_lines.append(line)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)
    
    print(f"Cleaned header saved to {output_file}")

if __name__ == '__main__':
    clean_psp_header('psp_signatures_final.h', 'psp_signatures_clean.h')
