"""Generate GB2312 Binary Table and Mapping File
// Input Space
// First Byte: 0xA1-0xF7
// Second Byte: 0xA1-0xFE
//
// Output Space: 0xA600-0xDDFF
// index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1);
// mapped_code = 0xA600 + index;
"""


def gb2312_convert(f, func):
    # 遍历所有可能的第一个字节
    for first_byte in range(0xA1, 0xF8):
        # 遍历所有可能的第二个字节
        for second_byte in range(0xA1, 0xFF):
            # 组合成一个 GB2312 编码的字节序列
            gb2312_bytes = bytes([first_byte, second_byte])

            try:
                # 将 GB2312 编码的字节序列解码为 Unicode 字符
                unicode_char = gb2312_bytes.decode("gb2312")

                # 将 Unicode 字符编码为 UTF-16
                utf16_bytes = unicode_char.encode("utf-16le")

                # 计算自定义编码
                index = (first_byte - 0xA1) * 94 + (second_byte - 0xA1)
                custom_code = 0xA600 + index

                # 写入 UTF-16 编码到文件
                func(f, unicode_char, utf16_bytes, custom_code)
            except UnicodeDecodeError:
                # 写入 0x0000 表示无效编码
                func(f, unicode_char, b"\x00\x00", custom_code)


def to_binary(f, unicode_char, utf16_bytes, custom_code):
    f.write(utf16_bytes)


def to_txt(f, unicode_char, utf16_bytes, custom_code):
    f.write(f"{unicode_char}\t{utf16_bytes.hex()}\t{hex(custom_code)}\n")


# 调用函数生成映射表
with open("gb2312_to_custom_map.txt", "w", encoding="utf-8") as f:
    gb2312_convert(f, to_txt)

# 调用函数生成二进制映射表
with open("GB_2312.bin", "wb") as f:
    gb2312_convert(f, to_binary)
