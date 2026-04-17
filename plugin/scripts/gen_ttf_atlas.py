from pathlib import Path
import argparse
from PIL import Image, ImageFont, ImageDraw

# --- 配置区 ---
FONT_SIZE = 14            # 字体大小
ATLAS_SIZE = 256          # 贴图尺寸
CELL_SIZE = 16            # 每个格子的尺寸 (16x16)
# --------------

def generate_atlas(
    font_path,
    chars_path,
    out_dir,
    header_path,
    font_size,
    atlas_size,
    cell_size,
):
    text_data = chars_path.read_text(encoding="utf-8").strip()
    chars = sorted(list(set(text_data)))
    font = ImageFont.truetype(str(font_path), font_size)
    atlas = Image.new('RGBA', (atlas_size, atlas_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(atlas)
    
    char_info = []

    for i, char in enumerate(chars):
        if i >= (atlas_size // cell_size) ** 2:
            print("警告：贴图空间不足，部分字符被忽略")
            break
            
        row = i // (atlas_size // cell_size)
        col = i % (atlas_size // cell_size)
        x = col * cell_size
        y = row * cell_size
        
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
    
    out_dir.mkdir(parents=True, exist_ok=True)
    header_path.parent.mkdir(parents=True, exist_ok=True)

    atlas_bin_path = out_dir / "atlas.bin"
    atlas_palette_path = out_dir / "atlas_palette.bin"

    with atlas_bin_path.open("wb") as f:
        f.write(index_data)  # 64KB (256*256)
    
    with atlas_palette_path.open("wb") as f:
        f.write(bytes(palette))  # 1KB (256*4)

    # 2. 生成 C 头文件
    with header_path.open("w", encoding="utf-8") as f:
        f.write("#ifndef __ATLAS_DATA_H__\n#define __ATLAS_DATA_H__\n\n")
        f.write(f"#define ATLAS_CHAR_COUNT {len(char_info)}\n\n")
        
        f.write("typedef struct { unsigned short code; unsigned char width; } CharIndex;\n\n")
        
        f.write("static const CharIndex atlas_index[] = {\n")
        for info in char_info:
            f.write(f"    {{ 0x{info['code']:04X}, {info['width']} }},\n")
        f.write("};\n\n#endif\n")
        
    print(f"成功生成！共 {len(char_info)} 个字符")
    print(f"索引贴图: {atlas_bin_path} ({len(index_data)} bytes)")
    print(f"调色板: {atlas_palette_path} ({len(palette)} bytes)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the loader UI font atlas.")
    parser.add_argument("--font", type=Path, required=True, help="TTF font path.")
    parser.add_argument(
        "--chars",
        type=Path,
        required=True,
        help="UTF-8 text file containing every character required by the UI.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help="Directory for atlas.bin and atlas_palette.bin.",
    )
    parser.add_argument(
        "--header",
        type=Path,
        default=Path("atlas_data.h"),
        help="Output atlas_data.h path.",
    )
    parser.add_argument("--font-size", type=int, default=FONT_SIZE)
    parser.add_argument("--atlas-size", type=int, default=ATLAS_SIZE)
    parser.add_argument("--cell-size", type=int, default=CELL_SIZE)
    args = parser.parse_args()

    generate_atlas(
        args.font,
        args.chars,
        args.out_dir,
        args.header,
        args.font_size,
        args.atlas_size,
        args.cell_size,
    )
