import json
import rzpipe
from encoding.encode_new_table import CharTable

TABLE_ELF_ADDR = "0x22bb60"
# Generate the new table
tbl_hex_file = "./new_table_bin.txt"


class Patcher:
    def __init__(self):
        self.data = None
        self.table = None

    # Load Translation downloaded from Crowdin.
    def load_translation(self, json_file_path: str):
        with open(json_file_path, "r", encoding="utf-8") as json_file:
            self.data = json.load(json_file)

    # Load Table Json file
    def load_table(self, table_path: str):
        self.table = CharTable(table_path)

    @staticmethod
    def extract_technical(technical: str) -> tuple[str, str, int]:
        # elf:data:0x0025089C,ram:0x08A5489C,size:24
        parts = technical.split(",")
        elf_data = parts[0].split(":")[2]  # 0x0025089C
        ram_data = parts[1].split(":")[1]  # 0x08A5489C
        size = int(parts[2].split(":")[1])  # 24

        # print("elf_data:", elf_data)
        # print("ram_data:", ram_data)
        # print("size:", size)
        return (elf_data, ram_data, size)

    def patch_translation(self, eboot_filepath: str):
        fail = 0
        success = 0
        with rzpipe.open(eboot_filepath, flags=["-w"]) as rz:
            for elem in self.data:
                elf_vmaddr, _, size = self.extract_technical(elem["key"])
                print(elem["translation"])
                hex_str = self.table.convert_str_to_hex(elem["translation"])
                if len(hex_str) > size * 2:
                    print("hex_str is too long")
                    fail += 1
                    print(f"Failed: {elem['source_string']}")
                    continue
                print(rz.cmd(f"wx {hex_str} @ {elf_vmaddr}"))
                print(rz.cmd(f"px {size} @ {elf_vmaddr}"))
                success += 1
        print(f"Failed: {fail}")
        print(f"Success: {success}")

    def patch_table(self, eboot_filepath: str):
        # Generate a temporary file with the new table in hex format.
        self.table.save_table_hex_str(tbl_hex_file)
        # Patch the ELF with the modified UTF-16 table.
        with rzpipe.open(eboot_filepath, flags=["-w"]) as rz:
            print(rz.cmd(f"s {TABLE_ELF_ADDR}"))
            print(rz.cmd(f"px 10"))
            print(rz.cmd(f"wxf {tbl_hex_file}"))
            print(rz.cmd(f"px 10"))

    def patch(self, eboot_filepath: str):
        self.patch_table(eboot_filepath)
        self.patch_translation(eboot_filepath)


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        prog="ELF Patcher", description="Patch ELF Encoding Table and SJIS Strings"
    )

    parser.add_argument("eboot_filepath")
    parser.add_argument("-t", "--translation_path")
    parser.add_argument("-e", "--table_path", required=True)

    args = parser.parse_args()
    print(args)
    
    patcher = Patcher()
    patcher.load_table(args.table_path)
    patcher.patch_table(args.eboot_filepath)
    if args.table_path != None:
        patcher.load_translation(args.translation_path)
        patcher.patch_translation(args.eboot_filepath)