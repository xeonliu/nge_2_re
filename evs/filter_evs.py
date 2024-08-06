import json
import os
import shutil
from collections import OrderedDict

# Load evs_say_params.json
with open("evs_say_params.json") as f:
    say_params = json.load(f)


def get_avatar_name(id):
    print(id)
    for key, value in say_params.items():
        if value["id"] == id:
            return key
    return None


def get_facial_expression_name(name, id):
    for key, value in say_params[name]["expression"].items():
        if value == id:
            return key
    return None


def generate_crowdin_entry(id, content, context):
    return None


# Process Function 1 Entry
def process_entry(entry):
    params = entry["parameters"]
    avatar: int = params[0]
    facial_expression: int = params[1]
    audio: int = params[2]

    avatar_name = "Default"
    facial_expression_name = "Default"

    if get_avatar_name(avatar) != None:
        avatar_name = get_avatar_name(avatar)
        facial_expression_name = get_facial_expression_name(
            avatar_name, facial_expression
        )
    content = entry["content"]
    contex_str = f"avatar: {avatar_name}, facial_expression: {facial_expression_name}, audio: {audio}"
    print(content, contex_str)
    return (content, contex_str)


# process_entry(
#     {
#             "function": 1,
#             "parameters": [
#                 70,
#                 12288,
#                 26095
#             ],
#             "content": "本日１２時３０分。▽\n"
#         }
# )

"""
Copy src to dst and returns dst paths
"""


def copy_evs_files(src_dir, dst_dir) -> list[str]:
    evs_paths = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".EVS.json"):
                # 构建源文件路径
                src_file_path = os.path.join(root, file)

                # 构建目标文件路径
                relative_path = os.path.relpath(root, src_dir)
                dst_file_dir = os.path.join(dst_dir, relative_path)
                dst_file_path = os.path.join(dst_file_dir, file)

                # 创建目标目录（如果不存在）
                os.makedirs(dst_file_dir, exist_ok=True)

                # 复制文件
                shutil.copy2(src_file_path, dst_file_path)
                print(f"Copied {src_file_path} to {dst_file_path}")
                evs_paths.append(dst_file_path)
    return evs_paths


def get_evs_paths(src_dir):
    evs_paths = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".EVS.json"):
                # 构建源文件路径
                src_file_path = os.path.join(root, file)
                print(f"Found {src_file_path}")
                evs_paths.append(src_file_path)
    return evs_paths


if __name__ == "__main__":
    import sys
    import glob

    module_dir = os.path.dirname(os.path.abspath(__file__))
    print(module_dir)

    json_files = get_evs_paths(os.path.join(module_dir, "test"))
    print(json_files)
    for json_file in json_files:
        evs_json_name = os.path.basename(json_file)
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=OrderedDict)["entries"]
        extracted_evs = []

        for elem in data:
            if elem["function"] == 1:
                content, context = process_entry(elem)
                extracted_evs.append(
                    {
                        "key": evs_json_name + str(hash(content + context)),
                        "original": content,
                        "translation": None,
                        "context": context,
                        # "label": evs_json_name,
                    }
                )

        print(extracted_evs)

        import pandas as pd

        df = pd.DataFrame(extracted_evs)
        df.to_csv("./filtered/" + evs_json_name + ".csv", header=False, index=False)
        # df.to_excel("./filtered/test" + evs_json_name + ".xlsx", index=False)
