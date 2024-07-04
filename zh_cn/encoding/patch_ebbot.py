import json
from collections import Counter, OrderedDict
import binascii

"""
Patch ELF using the new table.
"""

str = "我能吞下玻璃\n而不伤身体。"
# Create a new dictionary with reversed key-value pairs
reverse_data = {v: k for k, v in data.items()}

# Encode the string
# if char in ascii, do nothing, else replace with reverse_data[char]
encoded_s = [reverse_data[char] if char in reverse_data else "0x"+ binascii.hexlify(char.encode('ascii')).decode('ascii') for char in str]

# Print the result
print(encoded_s)

# ['0x89e4', '0x945c', '0x82a1', '0x89ba', '0xe0de', '0x979e', '0x8ea7', '0x9573', '0x82a7', '0x9067', '0x91cc', '0x82aa']
hex_string = "".join(s[2:] for s in encoded_s)
hex_string += "0000"  # Add a null terminator
print(hex_string)
# 89e4945c82a189bae0de979e8ea7957382a7906791cc82aa0000
# Store in Big Endian
# Test on 0x001B1880

import rzpipe

eboot_file = "../eboot/EBOOT.BIN"

with rzpipe.open(eboot_file, flags=["-w"]) as rz:
    print(rz.cmd(f"wx {hex_string} @ 0x001B1880"))
    print(rz.cmd(f"px 10 @ 0x001B1880"))
