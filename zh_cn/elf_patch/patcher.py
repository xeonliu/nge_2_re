import json
import rzpipe
from tools.common import to_eva_sjis
class Patcher:
    def __init__(self):
        self.data = None

    # Load Translation downloaded from Crowdin.
    def load_translation(self, json_file_path: str):
        with open(json_file_path, "r", encoding="utf-8") as json_file:
            self.data = json.load(json_file)

    @staticmethod
    def extract_technical(technical: str) -> tuple[str, str, int]:
        # elf:data:0x0025089C,ram:0x08A5489C,size:24
        parts = technical.split(",")
        elf_data = parts[0].split(":")[2]  # 0x0025089C
        ram_data = parts[1].split(":")[1]  # 0x08A5489C
        size = int(parts[2].split(":")[1].split('\n')[0])  # 24

        # print("elf_data:", elf_data)
        # print("ram_data:", ram_data)
        # print("size:", size)
        return (elf_data, ram_data, size)

    def patch_translation(self, eboot_filepath: str):
        fails = []
        success = 0
        with rzpipe.open(eboot_filepath, flags=["-w"]) as rz:
            for elem in self.data:
                """
                {
                    "key": "elf:rodata:0x001D144C,ram:0x089D544C,size:20",
                    "original": "●戦闘デモテスト",
                    "translation": "战斗演示试验",
                    "stage": 1,
                    "context": "elf:rodata:0x001D144C,ram:0x089D544C,size:20\n106"
                },
                """
                elf_vmaddr, _, size = self.extract_technical(elem["key"])
                print(elem["translation"])
                original_bytes = to_eva_sjis(elem["original"])
                translation_bytes = to_eva_sjis(elem["translation"])
                hex = translation_bytes.hex() + b"\x00".hex()
                if len(translation_bytes) > len(original_bytes):
                    fails.append(elem)
                    print(f"Failed: {elem['original']}")
                    continue
                print(rz.cmd(f"wx {hex} @ {elf_vmaddr}"))
                print(rz.cmd(f"px {size} @ {elf_vmaddr}"))
                success += 1
        print(f"Success: {success}")
        return fails

    def patch(self, eboot_filepath: str):
        self.patch_translation(eboot_filepath)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog="ELF Patcher", description="Patch ELF Encoding Table and SJIS Strings"
    )

    parser.add_argument("eboot_filepath")
    parser.add_argument("-t", "--translation_path")

    args = parser.parse_args()
    print(args)
    
    patcher = Patcher()
    patcher.load_translation(args.translation_path)
    fails = patcher.patch_translation(args.eboot_filepath)
    print(f"Fails: {len(fails)}")
    with open("fails.json", "w") as f:
        json.dump(fails, f, indent=4, ensure_ascii=False)