import sys
from PIL import Image, ImageFont, ImageDraw

# --- 配置区 ---
FONT_PATH = "ChillRoundFBold.ttf"  # 替换为你电脑上的字体路径
FONT_SIZE = 14            # 字体大小
ATLAS_SIZE = 256          # 贴图尺寸
CELL_SIZE = 16            # 每个格子的尺寸 (16x16)
# 你需要的所有字符
TEXT_DATA = "开启内存补丁显示系统信息详细按START启动游戏加载中完成错误版本:. 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
# --------------

def generate_atlas():
    chars = sorted(list(set(TEXT_DATA)))
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    atlas = Image.new('RGBA', (ATLAS_SIZE, ATLAS_SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(atlas)
    
    char_info = []

    for i, char in enumerate(chars):
        if i >= (ATLAS_SIZE // CELL_SIZE) ** 2:
            print("警告：贴图空间不足，部分字符被忽略")
            break
            
        row = i // (ATLAS_SIZE // CELL_SIZE)
        col = i % (ATLAS_SIZE // CELL_SIZE)
        x = col * CELL_SIZE
        y = row * CELL_SIZE
        
        # 渲染字符 (支持抗锯齿)
        draw.text((x, y), char, font=font, fill=(255, 255, 255, 255))
        
        # 获取字符的实际渲染宽度
        bbox = font.getbbox(char)
        width = bbox[2] - bbox[0] if bbox else 8
        char_info.append({
            'code': ord(char),
            'width': width,
            'x': x,
            'y': y
        })

    # 1. 转换为 8 位索引格式 (T8)
    # 使用灰度值作为索引，构建 256 色调色板（从透明到白色的渐变）
    gray_img = atlas.convert('L')  # 转换为灰度
    alpha_channel = atlas.split()[3]  # 提取 alpha 通道
    
    # 生成调色板：256级灰度，带alpha渐变
    palette = []
    for i in range(256):
        # ABGR8888 格式：白色文字，alpha从0到255
        a = i
        b = 255
        g = 255
        r = 255
        palette.extend([r, g, b, a])
    
    # 保存索引数据（使用alpha通道作为索引）
    index_data = alpha_channel.tobytes()
    
    with open("atlas.bin", "wb") as f:
        f.write(index_data)  # 64KB (256*256)
    
    with open("atlas_palette.bin", "wb") as f:
        f.write(bytes(palette))  # 1KB (256*4)

    # 2. 生成 C 头文件
    with open("atlas_data.h", "w", encoding="utf-8") as f:
        f.write("#ifndef __ATLAS_DATA_H__\n#define __ATLAS_DATA_H__\n\n")
        f.write(f"#define ATLAS_CHAR_COUNT {len(char_info)}\n\n")
        
        f.write("typedef struct { unsigned short code; unsigned char width; } CharIndex;\n\n")
        
        f.write("static const CharIndex atlas_index[] = {\n")
        for info in char_info:
            f.write(f"    {{ 0x{info['code']:04X}, {info['width']} }},\n")
        f.write("};\n\n#endif\n")
        
    print(f"成功生成！共 {len(char_info)} 个字符")
    print(f"索引贴图: atlas.bin ({len(index_data)} bytes)")
    print(f"调色板: atlas_palette.bin ({len(palette)} bytes)")

if __name__ == "__main__":
    generate_atlas()