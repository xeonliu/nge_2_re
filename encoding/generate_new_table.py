import json
from collections import Counter, OrderedDict

# Specify the path to your JSON file
json_file_path = "./output2.json"

# Open the JSON file and load its contents
with open(json_file_path, "r", encoding="utf-8") as json_file:
    data = json.load(json_file, object_pairs_hook=OrderedDict)

# Input string and character counting
test_str = "我能吞下玻璃而不伤身体我。"
char_count = Counter(test_str)
sorted_char_count = sorted(char_count.items(), key=lambda x: x[1], reverse=True)

# Replace the values in the JSON data
char_iter = iter(char for char, _ in sorted_char_count)
for key in data.keys():
    if int(key,16) >= 0x829f:
        try:
            data[key] = next(char_iter)
        except StopIteration:
            break  # No more characters to replace with

# Print the modified data
for k, v in data.items():
    print(k, v)

new_json_file_path = "./new.json"

# Optionally, save the modified JSON back to the file
with open(new_json_file_path, 'w', encoding="utf-8") as json_file:
    json.dump(data, json_file, ensure_ascii=False, indent=4)