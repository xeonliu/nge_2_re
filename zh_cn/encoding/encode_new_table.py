"""
Generate a encoding table & Modified UTF-16 Table according to character used in text.
"""

import json
import re
import binascii
from collections import Counter, OrderedDict


class CharTable:
    """
    The Encoding Table is stored in this way: 0x20: " "
    """

    data: dict[str, str]

    def __init__(self, json_file_path):
        with open(json_file_path, "r", encoding="utf-8") as json_file:
            self.data = json.load(json_file, object_pairs_hook=OrderedDict)

    """
    Return a list of (character, number) pair in descing order.
    """

    def get_sorted_char_count(self, test_str: str) -> dict[str, str]:
        # Only keep characters that are not ASCII
        filtered_str = "".join(char for char in test_str if not char.isascii())
        # Remove non-Chinese characters
        # filtered_str = re.sub(r'[^\u4e00-\u9fff]', '', test_str)
        char_count = Counter(filtered_str)
        return sorted(char_count.items(), key=lambda x: x[1], reverse=True)

    """
    Provided translated strings, replace the existing Encoding Table with new characters.
    """

    def replace_chars(self, test_str):
        # Get count first
        sorted_char_count = self.get_sorted_char_count(test_str)
        print(sorted_char_count)
        char_iter = iter(char for char, _ in sorted_char_count)
        for key in self.data.keys():
            if int(key, 16) >= 0x829F and int(key, 16) <= 0xEAA4:
                # if int(key, 16) >= 0x8140:
                try:
                    curr_char = next(char_iter)
                    # if curr_char not in self.data.values():
                    self.data[key] = curr_char
                except StopIteration:
                    print("All chacaters are replaced")
                    break  # No more characters to replace with

    """
    Save the new Encoding Table in json
    """

    def save_to_json(self, new_json_file_path):
        with open(new_json_file_path, "w", encoding="utf-8") as json_file:
            json.dump(self.data, json_file, ensure_ascii=False, indent=4)

    """
    Save the Encoding Table in a hex string format for patch on .BIN
    """

    def save_table_hex_str(self, output_file_path):
        tbl_bstream_arr = [v.encode("utf-16-le") for _, v in self.data.items()]
        tbl_hex_arr = [binascii.hexlify(bs).decode("utf-8") for bs in tbl_bstream_arr]
        tbl_hex_str = "".join(s for s in tbl_hex_arr)
        with open(output_file_path, "w", encoding="utf-8") as output_file:
            output_file.write(tbl_hex_str)

    """
    Encode a UTF-8 string into SJIS hex string format using the Encoding Table
    """

    def convert_str_to_hex(self, test_str: str):
        reversed_data = {v: k for k, v in self.data.items()}

        # ['0x89e4', '0x945c', '0x82a1', '0x89ba', '0xe0de', '0x979e', '0x8ea7', '0x9573', '0x82a7', '0x9067', '0x91cc', '0x82aa']
        encoded_s = []
        for char in test_str:
            # First try in ASCII
            try:
                encoded_char = encoded_char = "0x" + binascii.hexlify(
                    char.encode("ascii")
                ).decode("ascii")
                encoded_s.append(encoded_char)
            except:
                # Try in Table
                if char in reversed_data:
                    encoded_s.append(reversed_data[char])
                else:
                    # Try in S-JIS
                    try:
                        encoded_char = "0x" + binascii.hexlify(
                            char.encode("sjis")
                        ).decode("ascii")
                    except UnicodeEncodeError:
                        # TODO: Deal with Symbols that doesn't exist in table.
                        print("Error on char", char)
                        encoded_char = "0x3f"
                    encoded_s.append(encoded_char)

        hex_str = "".join(s[2:] for s in encoded_s)
        hex_str += "0000"  # Add a null terminator
        return hex_str

    """
    Encode a string into an unreadable UTF16 string
    """

    def convert_str_to_hex_stream(self, test_str: str) -> bytes:
        string = self.convert_str_to_hex(test_str)
        return binascii.unhexlify(string)


# Specify the path to your JSON file
import os

# 获取当前文件所在的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 动态设置文件路径
sjis_table_path = os.path.join(current_dir, "parse_bin", "decoded_sjis_table.json")
new_table_path = os.path.join(current_dir, "new_table.json")
new_table_hex_str = os.path.join(current_dir, "new_table_bin.txt")

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
