import json
import sys
import argparse
import os

parser = argparse.ArgumentParser(prog="TEXT Extract")

parser.add_argument("text_json_folder")
parser.add_argument("new_path")

args = parser.parse_args()

"""
Load all text json in the folder
"""
data = []
for root, dir, files in os.walk(args.text_json_folder):
    for file in files:
        if file.endswith(".TEXT.json"):
            src_file_path = os.path.join(root, file)
            with open(src_file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f)["strings"])


json_for_upload = []

for elem in data:
    s = {}
    s["key"] = str(hash(elem[2]))
    s["original"] = elem[2]
    json_for_upload.append(s)


with open(args.new_path, "w", encoding="utf-8") as f:
    json.dump(json_for_upload, f, ensure_ascii=False, indent=4)
