import json
import struct

import argparse

from app.parser import tools

class TranslationHeader:
    STRUCT_FORMAT = "<I"  # Little-endian, 1 unsigned int (u32)

    def __init__(self, num: int):
        self.num = num

    @classmethod
    def from_bytes(cls, data: bytes):
        num, = struct.unpack(cls.STRUCT_FORMAT, data[:4])
        return cls(num)

    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT_FORMAT, self.num)


class TranslationEntry:
    STRUCT_FORMAT = "<II1024s"  # Little-endian, 2 unsigned ints and 1024 bytes

    def __init__(self, offset: int, size: int, buffer: bytes):
        self.offset = offset
        self.size = size
        self.buffer = buffer.ljust(1024, b'\x00')[:1024]

    @classmethod
    def from_bytes(cls, data: bytes):
        offset, size, buffer = struct.unpack(cls.STRUCT_FORMAT, data[:1032])
        return cls(offset, size, buffer)

    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT_FORMAT, self.offset, self.size, self.buffer)


class Patcher:
    def __init__(self):
        self.data = None

    # Load Translation downloaded from Crowdin.
    def load_translation(self, path: str):
        """加载翻译数据，支持单个文件或目录（自动合并所有 chunk_*.json）"""
        import glob
        import os

        if os.path.isfile(path):
            # 单个文件
            with open(path, "r", encoding="utf-8") as json_file:
                self.data = json.load(json_file)
        elif os.path.isdir(path):
            # 目录：合并所有 chunk_*.json 文件
            pattern = os.path.join(path, "chunk_*.json")
            chunk_files = sorted(glob.glob(pattern))

            if not chunk_files:
                raise ValueError(f"No chunk_*.json files found in directory: {path}")

            print(f"Found {len(chunk_files)} chunk files, merging...")
            self.data = []
            for chunk_file in chunk_files:
                with open(chunk_file, "r", encoding="utf-8") as json_file:
                    chunk_data = json.load(json_file)
                    self.data.extend(chunk_data)
                    print(f"  Loaded {os.path.basename(chunk_file)}: {len(chunk_data)} entries")
            print(f"Total entries loaded: {len(self.data)}")
        else:
            raise ValueError(f"Path does not exist: {path}")

    @staticmethod
    def extract_technical(technical: str) -> tuple[str, str, int]:
        # elf:data:0x0025089C,ram:0x08A5489C,size:24
        parts = technical.split(",")
        elf_data = parts[0].split(":")[2]  # 0x0025089C
        ram_data = parts[1].split(":")[1]  # 0x08A5489C
        size = int(parts[2].split(":")[1].split("\n")[0])  # 24

        # print("elf_data:", elf_data)
        # print("ram_data:", ram_data)
        # print("size:", size)
        return (elf_data, ram_data, size)

    def patch_translation(self) -> list:
        entries = []
        
        # 首先按照地址排序所有条目
        sorted_data = sorted(self.data, key=lambda x: int(self.extract_technical(x["context"])[0], 16))
        
        for i, elem in enumerate(sorted_data):
            """
            {
                "key": "elf:rodata:0x001D144C,ram:0x089D544C,size:20",
                "original": "●戦闘デモテスト",
                "translation": "战斗演示试验",
                "stage": 1,
                "context": "elf:rodata:0x001D144C,ram:0x089D544C,size:20\n106"
            },
            """
            elf_vmaddr, ram_vmaddr, size = self.extract_technical(elem["context"])
            current_offset = int(elf_vmaddr, 16)
            
            print(elem["translation"])
            original_bytes = tools.to_eva_sjis(elem["original"])
            translation_bytes = tools.to_eva_sjis(elem["translation"])
            
            # 计算翻译文本需要的空间（包括结尾的 \0）
            required_space = len(translation_bytes) + 1
            
            # 计算可用空间：如果有下一个条目，用下一个地址减去当前地址；否则使用原始 size
            if i + 1 < len(sorted_data):
                next_elf_vmaddr, _, _ = self.extract_technical(sorted_data[i + 1]["context"])
                next_offset = int(next_elf_vmaddr, 16)
                available_space = next_offset - current_offset
            else:
                available_space = size
            
            # 检查空间是否足够（仅在翻译比原文长时才报错）
            if required_space > available_space and len(translation_bytes) > len(original_bytes):
                print(f"Failed: {elem['translation']} (需要 {required_space} 字节，可用 {available_space} 字节)，原文：{len(original_bytes) + 1}字节")
                continue
            if len(translation_bytes) > 1023:
                print(f"Failed: {elem['translation']} (翻译文本超过 1023 字节限制)")
                continue
            
            if len(translation_bytes) == len(original_bytes):
                hex = translation_bytes.hex()
            else:
                hex = translation_bytes.hex() + b"\x00".hex()
            
            buffer = bytes.fromhex(hex)
            
            entry = TranslationEntry(
                offset=int(ram_vmaddr, 16),
                size=len(buffer),
                buffer=buffer
            )

            entries.append(entry)
        return entries

    def patch(self, eboot_filepath: str):
        self.patch_translation(eboot_filepath)


if __name__ == "__main__":
  
    import sys
    import os
    parser = argparse.ArgumentParser(
        prog="ELF Patcher", description="Patch ELF Encoding Table and SJIS Strings"
    )

    parser.add_argument("-t", "--translation_path", required=True, help="Path to translation JSON file or directory containing chunk_*.json files")
    parser.add_argument("-o", help="Output file path", default="EBTRANS.BIN")
    args = parser.parse_args()

    # 检查 translation_path 是否存在
    if not os.path.exists(args.translation_path):
        print(f"Error: Translation path '{args.translation_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # 检查输出路径是否可写
    out_dir = os.path.dirname(args.o) or '.'
    if not os.access(out_dir, os.W_OK):
        print(f"Error: Output directory '{out_dir}' is not writable.", file=sys.stderr)
        sys.exit(1)

    patcher = Patcher()
    try:
        patcher.load_translation(args.translation_path)
    except Exception as e:
        print(f"Error loading translation file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        entries = patcher.patch_translation()
    except Exception as e:
        print(f"Error processing translation entries: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Success: {len(entries)}")

    header = TranslationHeader(num=len(entries))
    try:
        with open(args.o, "wb") as f:
            f.write(header.to_bytes())
            for entry in entries:
                f.write(entry.to_bytes())
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)