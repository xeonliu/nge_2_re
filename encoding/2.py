import binascii
import json

# 从文件中读取十六进制字符串
with open('1.txt', 'r') as f:
    hex_string_1 = f.read().replace(' ', '').replace('\n', '')

# 将十六进制字符串转换为字节序列
bytes_seq_1 = binascii.unhexlify(hex_string_1)

# 将字节序列解码为UTF-16字符串
utf16_string_1 = bytes_seq_1.decode('utf-16')

# 从文件中读取十六进制字符串
with open('mb.txt', 'r') as f:
    hex_string_mb = f.read().replace(' ', '').replace('\n', '')

import struct

byte_char_dict = {}
# 解析mb.txt中的字节序列
for i in range(0, len(hex_string_mb) - 8, 8):
    # 前两个字节代表编码的起始
    # start_code = int(hex_string_mb[i:i+4], 16)
    start_code = struct.unpack('<H', bytes.fromhex(hex_string_mb[i:i+4]))[0]
    # print(start_code)
    # 后两个字节代表编码的范围
    next_offset = struct.unpack('<H', bytes.fromhex(hex_string_mb[i+12:i+16]))[0]
    current_offset = struct.unpack('<H', bytes.fromhex(hex_string_mb[i+4:i+8]))[0]
    range_code = next_offset - current_offset
    # print(range_code)
    # 对于每个编码在范围内的字符
    for j in range(range_code):
        # 计算编码
        code = start_code + j
        # 从1.txt中获取对应的字符
        char = utf16_string_1[current_offset + j]
        # print(current_offset + j, char, "0x{:04x}".format(code))
        # 将编码和字符添加到字典中
        byte_char_dict[str(hex(code))] = char

# 处理剩余编码
start_code = struct.unpack('<H', bytes.fromhex(hex_string_mb[-8:-4]))[0]
range_code = 218
for j in range(range_code):
    code = start_code + j
    char = utf16_string_1[struct.unpack('<H', bytes.fromhex(hex_string_mb[-4:]))[0] + j]
    byte_char_dict[str(hex(code))] = char
    # print(current_offset + j, char, "0x{:04x}".format(code))
    # print(j)

# 将字典写入JSON文件
with open('output2.json', 'w', encoding='utf-8') as f:
    json.dump(byte_char_dict, f, ensure_ascii=False, indent=4)