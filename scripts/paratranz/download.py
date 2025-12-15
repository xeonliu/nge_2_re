"""
Docstring for scripts.paratranz.download
This script downloads translation files from Paratranz for a specific project,
unzips them, processes JSON files to replace newline characters and compute MD5 hashes for keys,
and combines EBOOT and EVS translations into separate JSON files.

NOTE THAT '\n' IN PARATRANZ IS '\\n', SO WE NEED TO CONVERT IT BACK TO REAL NEWLINE WHEN PROCESSING.
"""
import requests
import zipfile
import os
import argparse
import json
import hashlib

project_id = 10882  # 替换为你的项目ID

def download_and_process(
    auth_key: str,
    dest_folder: str = "temp/downloads",
    project_id_override: int | None = None,
):
    if project_id_override is not None:
        global project_id
        project_id = project_id_override

    if not auth_key:
        raise ValueError("AUTH_KEY 不能为空")

    url = f"https://paratranz.cn/api/projects/{project_id}/artifacts/download"

    zip_path = download_file(url, dest_folder, auth_key)
    print("Files have been downloaded.")

    if zip_path:
        unzip_file(zip_path, dest_folder)
        print(f"Files extracted to {dest_folder}")

    # ===== 后面的逻辑几乎原封不动 =====
    process_utf8_json(dest_folder)
    combine_eboot(dest_folder)
    combine_evs(dest_folder)

def process_utf8_json(dest_folder):
    free_path = os.path.join(dest_folder, "utf8", "free")
    game_path = os.path.join(dest_folder, "utf8", "game")
    if os.path.exists(free_path):
        print("Processing JSON files in utf8/free and utf8/game folders...")
        for file in os.listdir(free_path):
            if file.endswith(".json"):
                file_path = os.path.join(free_path, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data = hash_keys_in_data(data, normalize_newlines=True)
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=4)
                print(f"  Processed: {file_path}")
        
        if os.path.exists(game_path):
            for file in os.listdir(game_path):
                if file.endswith(".json"):
                    file_path = os.path.join(game_path, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    data = hash_keys_in_data(data, normalize_newlines=True)
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=4)
                    print(f"  Processed: {file_path}")
                    
def combine_eboot(dest_folder):
    # Combine all the EBOOT Translations.
    eboot_path = os.path.join(dest_folder, "raw", "EBOOT")
    data = []
    for root, dir, files in os.walk(eboot_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f))
    data = replace_newlines(data)
    data = hash_keys_in_data(data)
    eboot_trans = os.path.join(dest_folder, "eboot_trans.json")
    with open(eboot_trans, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
        
def combine_evs(dest_folder):
    # Combine the EVS translations
    evs_path = os.path.join(dest_folder, "raw", "EVS")
    data = []
    for root, dir, files in os.walk(evs_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f))
    data = replace_newlines(data)
    data = hash_keys_in_data(data)
    evs_trans = os.path.join(dest_folder, "evs_trans.json")
    with open(evs_trans, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    


def update_string(key: str, content: str, auth, stage=2):
    # sleep for 1 second to avoid rate limit
    import time

    time.sleep(0.5)
    items = search_by_key(key, auth)
    for item in items:
        if item["stage"] == stage:
            print(f"Already in stage {stage}")
            continue
        id = item["id"]
        if content != "":
            add_comment(id, content, auth)
        print(update_status(id, stage, auth))


# 查找到字符串ID
def search_by_key(key, auth):
    url = f"https://paratranz.cn/api/projects/{project_id}/strings?text={key}"
    headers = {"Authorization": auth}
    response = requests.get(url, headers=headers).json()
    items = [item for item in response["results"]]
    return items


# 添加评论
def add_comment(string_id, content: str, auth):
    url = "https://paratranz.cn/api/comments"
    headers = {"Authorization": auth}
    data = {"type": "text", "tid": string_id, "content": content}
    response = requests.post(url, headers=headers, json=data)
    return response.json()


# 更新有疑问状态
def update_status(string_id, stage, auth):
    url = f"https://paratranz.cn/api/projects/{project_id}/strings/{string_id}"
    headers = {"Authorization": auth}
    data = {"stage": stage}
    response = requests.put(url, headers=headers, json=data)
    return response.json()


def download_file(url, dest_folder, auth: str):
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)

    headers = {"Authorization": auth}
    response = requests.get(url, headers=headers, stream=True)
    if response.status_code == 302:
        download_url = response.headers["Location"]
        response = requests.get(download_url, headers=headers, stream=True)

    if response.status_code == 200:
        zip_path = os.path.join(dest_folder, "downloaded.zip")
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=128):
                f.write(chunk)
        return zip_path
    else:
        print(f"Error: {response.status_code}")
        return None


def unzip_file(zip_path, dest_folder):
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(dest_folder)


def replace_newlines(obj):
    if isinstance(obj, str):
        return obj.replace("\\n", "\n")
    elif isinstance(obj, list):
        return [replace_newlines(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: replace_newlines(value) for key, value in obj.items()}
    return obj


def hash_keys_in_data(data, normalize_newlines=False):
    """将 JSON 数据中的 key 替换为 original 的 MD5 哈希值
    
    Args:
        data: JSON 数据
        normalize_newlines: 是否将 \\n 转换为真实换行符再计算 hash
    """
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "original" in item:
                original_text = item["original"]
                # 如果需要标准化换行符，将 \n 转换为真实换行
                if normalize_newlines:
                    original_text = original_text.replace("\\n", "\n")
                hash_object = hashlib.md5(original_text.encode())
                item["key"] = hash_object.hexdigest()
                item["original"] = original_text
    return data


if __name__ == "__main__":
    # Add Arguments
    parser = argparse.ArgumentParser(
        description="Download and process Paratranz files."
    )
    parser.add_argument(
        "--dest_folder",
        type=str,
        default="data/pz_downloads",
        help="Destination folder for downloaded files.",
    )
    args = parser.parse_args()
    dest_folder = args.dest_folder
    
    auth_key = os.getenv("AUTH_KEY")
    if not auth_key:
        raise ValueError("AUTH_KEY环境变量未设置")
    
    download_and_process(
        auth_key,
        dest_folder,
    )

