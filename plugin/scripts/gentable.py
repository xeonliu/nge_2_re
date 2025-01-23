"""
// Input Space
// First Byte: 0xA1-0xF7
// Second Byte: 0xA1-0xFE
// 
// Output Space: 0xA600-0xDDFF
// index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1);
// mapped_code = 0xA600 + index;
"""

import codecs

def gb2312_to_custom():
    # 打开文件以写入映射表
    with open('gb2312_to_custom_map.txt', 'w', encoding='utf-8') as f:
        # 遍历所有可能的第一个字节
        for first_byte in range(0xA1, 0xF8):
            # 遍历所有可能的第二个字节
            for second_byte in range(0xA1, 0xFF):
                # 组合成一个 GB2312 编码的字节序列
                gb2312_bytes = bytes([first_byte, second_byte])
                
                try:
                    # 将 GB2312 编码的字节序列解码为 Unicode 字符
                    unicode_char = gb2312_bytes.decode('gb2312')

                    # 将 Unicode 字符编码为 UTF-16
                    utf16_bytes = unicode_char.encode('utf-16be').hex()
                    
                    # 计算自定义编码
                    index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1)
                    custom_code = 0xA600 + index
                    
                    # 写入映射表
                    f.write(f"{unicode_char}\t{utf16_bytes}\t{hex(custom_code)}\n")
                except UnicodeDecodeError:
                    # 跳过无效的 GB2312 编码
                    continue

def gb2312_to_utf16_binary():
    # 打开文件以写入二进制映射表
    with open('GB_2312.bin', 'wb') as f:
        # 遍历所有可能的第一个字节
        for first_byte in range(0xA1, 0xF8):
            # 遍历所有可能的第二个字节
            for second_byte in range(0xA1, 0xFF):
                # 组合成一个 GB2312 编码的字节序列
                gb2312_bytes = bytes([first_byte, second_byte])
                
                try:
                    # 将 GB2312 编码的字节序列解码为 Unicode 字符
                    unicode_char = gb2312_bytes.decode('gb2312')
                    
                    # 将 Unicode 字符编码为 UTF-16
                    utf16_bytes = unicode_char.encode('utf-16le')
                    
                    # 写入 UTF-16 编码到文件
                    f.write(utf16_bytes)
                except UnicodeDecodeError:
                    # 写入 0x0000 表示无效编码
                    f.write(b'\x00\x00')


# 调用函数生成映射表
gb2312_to_custom()
# 调用函数生成二进制映射表
gb2312_to_utf16_binary()