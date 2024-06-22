import json

eboot_json_path = "../translations/eboot.json"
with open(eboot_json_path, "r", encoding="utf-8") as eboot_json_file:
    data = json.load(eboot_json_file)

parsed_data = {}
english_trans = {}
objs = data["unsorted"]

for obj in objs:
    parsed_data[obj["technical"]] = obj["original"]
    english_trans[obj["technical"]] = obj["translation"]
    
print(parsed_data)

new_json_file_path = "./eboot_for_crowdin.json"

with open(new_json_file_path, 'w', encoding="utf-8") as json_file:
    json.dump(parsed_data, json_file, ensure_ascii=False, indent=4)

english_trans_file_path = "./eboot_english.json"
with open(english_trans_file_path, 'w', encoding="utf-8") as json_file:
    json.dump(english_trans, json_file, ensure_ascii=False, indent=4)