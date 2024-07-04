"""
Generate a encoding table & Modified UTF-16 Table according to character used in text.
"""

import json
import re
import binascii
from collections import Counter, OrderedDict


class CharTable:
    def __init__(self, json_file_path):
        with open(json_file_path, "r", encoding="utf-8") as json_file:
            self.data = json.load(json_file, object_pairs_hook=OrderedDict)

    def get_sorted_char_count(self, test_str):
        # Only keep characters that are not ASCII
        filtered_str = "".join(char for char in test_str if not char.isascii())
        # Remove non-Chinese characters
        # filtered_str = re.sub(r'[^\u4e00-\u9fff]', '', test_str)
        char_count = Counter(filtered_str)
        return sorted(char_count.items(), key=lambda x: x[1], reverse=True)

    def replace_chars(self, test_str):
        sorted_char_count = self.get_sorted_char_count(test_str)
        print(sorted_char_count)
        char_iter = iter(char for char, _ in sorted_char_count)
        for key in self.data.keys():
            # if int(key, 16) >= 0x829F:
            if int(key, 16) >= 0x8140:
                try:
                    curr_char = next(char_iter)
                    # if curr_char not in self.data.values():
                    self.data[key] = curr_char
                except StopIteration:
                    print("All chacaters are replaced")
                    break  # No more characters to replace with

    def save_to_json(self, new_json_file_path):
        with open(new_json_file_path, "w", encoding="utf-8") as json_file:
            json.dump(self.data, json_file, ensure_ascii=False, indent=4)

    def save_table_hex_str(self, output_file_path):
        tbl_bstream_arr = [v.encode("utf-16-le") for k, v in self.data.items()]
        tbl_hex_arr = [binascii.hexlify(bs).decode("utf-8") for bs in tbl_bstream_arr]
        tbl_hex_str = "".join(s for s in tbl_hex_arr)
        with open(output_file_path, "w", encoding="utf-8") as output_file:
            output_file.write(tbl_hex_str)

    def convert_str_to_hex(self, test_str: str):
        reversed_data = {v: k for k, v in self.data.items()}

        # ['0x89e4', '0x945c', '0x82a1', '0x89ba', '0xe0de', '0x979e', '0x8ea7', '0x9573', '0x82a7', '0x9067', '0x91cc', '0x82aa']
        encoded_s = [
            (
                reversed_data[char]
                if char in reversed_data
                else "0x" + binascii.hexlify(char.encode("ascii")).decode("ascii")
            )
            for char in test_str
        ]
        hex_str = "".join(s[2:] for s in encoded_s)
        hex_str += "0000"  # Add a null terminator
        return hex_str


# Specify the path to your JSON file
sjis_table_path = "./parse_bin/decoded_sjis_table.json"
new_table_path = "./new_table.json"
new_table_hex_str = "./new_table_bin.txt"
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python encode_new_table.py <text_file>")
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        text = f.read()
    char_table = CharTable(sjis_table_path)
    char_table.replace_chars(text)
    char_table.save_to_json(new_table_path)
    char_table.save_table_hex_str(new_table_hex_str)
