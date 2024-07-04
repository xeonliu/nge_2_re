import binascii
import json

# 从文件中读取十六进制字符串
with open('1.txt', 'r') as f:
    hex_string = f.read().replace(' ', '').replace('\n', '')

# 将十六进制字符串转换为字节序列
bytes_seq = binascii.unhexlify(hex_string)

# 将字节序列解码为UTF-16字符串
utf16_string = bytes_seq.decode('utf-16')

# 创建一个字典，其中每个字节对应一个字符
byte_char_dict = {hex_string[i:i+4]: utf16_string[i//4] for i in range(0, len(hex_string), 4)}

# 将字典写入JSON文件
with open('output.json', 'w', encoding='utf-8') as f:
    json.dump(byte_char_dict, f, ensure_ascii=False, indent=4)