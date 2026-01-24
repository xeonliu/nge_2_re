import sys
import gzip

def convert_hex_to_bin(input_file, output_file):
    # 初始化 2MB 的全 0 缓冲区 (65536 个字符 * 32 字节)
    font_buffer = bytearray(65536 * 32)
    
    # 检测是否是 .gz 文件
    open_func = gzip.open if input_file.endswith('.gz') else open
    
    with open_func(input_file, 'rt', encoding='ascii') as f:
        for line in f:
            if ':' not in line: continue
            
            code_hex, data_hex = line.strip().split(':')
            code = int(code_hex, 16)
            
            # 只处理基本多语言平面 (BMP, U+0000 - U+FFFF)
            if code > 0xFFFF: continue 
            
            # 将十六进制点阵字符串转为字节
            glyph_data = bytes.fromhex(data_hex)
            
            # 如果是 8x16 (16字节)，我们还是占 32 字节空间以便对齐索引
            # 存放在前 16 字节
            offset = code * 32
            font_buffer[offset:offset+len(glyph_data)] = glyph_data

    with open(output_file, 'wb') as f:
        f.write(font_buffer)
    print(f"Done! {output_file} generated.")

if __name__ == "__main__":
    # 使用方法: python hex2bin.py unifont-15.0.01.hex unifont.bin
    convert_hex_to_bin(sys.argv[1], sys.argv[2])