import json
import re
from collections import Counter, OrderedDict

# Specify the path to your JSON file
json_file_path = "./output2.json"

# Open the JSON file and load its contents
with open(json_file_path, "r", encoding="utf-8") as json_file:
    data = json.load(json_file, object_pairs_hook=OrderedDict)

# Input string and character counting
test_str = "我能吞下玻璃\n而不伤身体。"

# Only keep characters that are not ASCII
filtered_str = ''.join(char for char in test_str if not char.isascii())
# Remove non-Chinese characters
# filtered_str = re.sub(r'[^\u4e00-\u9fff]', '', test_str)
print(filtered_str)
char_count = Counter(filtered_str)
print(char_count)
sorted_char_count = sorted(char_count.items(), key=lambda x: x[1], reverse=True)

# Replace the values in the JSON data
char_iter = iter(char for char, _ in sorted_char_count)
for key in data.keys():
    # if int(key,16) >= 0x829f:
    if int(key,16) >= 0x8140:
        try:
            data[key] = next(char_iter)
        except StopIteration:
            break  # No more characters to replace with

# Print the modified data
# for k, v in data.items():
    # print(k, v)

new_json_file_path = "./new.json"

with open(new_json_file_path, 'w', encoding="utf-8") as json_file:
    json.dump(data, json_file, ensure_ascii=False, indent=4)