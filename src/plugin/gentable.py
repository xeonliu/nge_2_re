
# 需要Map记录GB2312到自定义编码的映射关系


def gb2312_to_custom():
    utf16s = []
    # 打开文件以写入映射表
    with open("gb2312_to_custom_map.txt", "w", encoding="utf-8") as f:
        # 映射表的空间很大，不需要考虑大小问题，只用避开0x25即可。
        i = 0
        custom_code = 0xA600
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
                    utf16_bytes = unicode_char.encode("utf-16be")

                    if (i % 0x100) == 0x25:
                        # 跳过 0x25
                        i += 1
                        utf16s.append(b"\x00\x00")

                    custom_code = 0xA600 + i

                    utf16s.append(utf16_bytes)

                    # 写入映射表
                    f.write(
                        f"{unicode_char}\t{utf16_bytes.hex()}\t{hex(custom_code)}\n"
                    )
                    i += 1
                except UnicodeDecodeError:
                    # 跳过无效的 GB2312 编码
                    continue
        # 合计 7445 个字符
        print(f"Used Space: 0xa600-{hex(custom_code)}")
        return utf16s


def write_to_utf16_binary(utf16s: list[bytes]):
    # 打开文件以写入二进制映射表
    with open("gb2312_to_utf16_map.bin", "wb") as f:
        # 遍历所有可能的第一个字节
        for utf16_bytes in utf16s:
            # 写入 UTF-16 编码到文件
            f.write(utf16_bytes)


# 调用函数生成映射表
bytes = gb2312_to_custom()

print(len(bytes))
# 调用函数生成二进制映射表
write_to_utf16_binary(bytes)
