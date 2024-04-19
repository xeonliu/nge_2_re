import json

# parse translation json
eboot_json = "../translations/eboot.json"

with open(eboot_json, 'r', encoding='utf-8') as f:
    translations = json.load(f)
    
print(translations)
