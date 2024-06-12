"""
Patch the table using key-value pairs.
"""

import json
from collections import Counter, OrderedDict
import binascii

json_file_path = "./new.json"
output_file_path = "./output.txt"

# Read in Table
with open(json_file_path, "r", encoding="utf-8") as json_file:
    data = json.load(json_file, object_pairs_hook=OrderedDict)

# Convert the table to a hex string
tbl_bstream_arr = [v.encode("utf-16-le") for k, v in data.items()]
# ['0x89e4', '0x945c' ... ]
tbl_hex_arr = [binascii.hexlify(bs).decode("utf-8") for bs in tbl_bstream_arr]
# '89e4945c...'
tbl_hex_str = "".join(s for s in tbl_hex_arr)

# Write the table to a file
with open(output_file_path, "w", encoding="utf-8") as output_file:
    output_file.write(tbl_hex_str)

# with open(output_file_path, "wb") as output_file:
#     for k, v in data.items():
#         b = v.encode('utf-16-le')
#         output_file.write(b)

"""
Patch ELF with the new table.
"""

str = "我能吞下玻璃而不伤身体。"
# Create a new dictionary with reversed key-value pairs
reverse_data = {v: k for k, v in data.items()}

# Encode the string
encoded_s = [reverse_data[char] for char in str if char in reverse_data]

# Print the result
print(encoded_s)

# ['0x89e4', '0x945c', '0x82a1', '0x89ba', '0xe0de', '0x979e', '0x8ea7', '0x9573', '0x82a7', '0x9067', '0x91cc', '0x82aa']
hex_string = "".join(s[2:] for s in encoded_s)
hex_string += "0000"  # Add a null terminator
print(hex_string)
# 89e4945c82a189bae0de979e8ea7957382a7906791cc82aa0000
# Store in Big Endian
# Test on 0x001B1880
