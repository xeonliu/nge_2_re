import requests
import zipfile
import os
import json

project_id = 10882  # 替换为你的项目ID
dest_folder = "downloads"


def update_string(key: str, content: str, auth, stage=2):
    # sleep for 1 second to avoid rate limit
    import time
    time.sleep(0.5)
    items = search_by_key(key, auth)
    for item in items:
        if(item["stage"] == stage):
            print(f"Already in stage {stage}")
            continue
        id = item["id"]
        if content!="":
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


if __name__ == "__main__":

    auth_key = os.getenv("AUTH_KEY")
    if not auth_key:
        raise ValueError("AUTH_KEY环境变量未设置")

    url = f"https://paratranz.cn/api/projects/{project_id}/artifacts/download"
    # Download files from paratranz.
    zip_path = download_file(url, dest_folder, auth_key)
    print("Files have been downloaded.")
    if zip_path:
        # Unzip them
        unzip_file(zip_path, dest_folder)
        print(f"Files have been downloaded and extracted to {dest_folder}")

    # Combine all the EBOOT Translations.
    eboot_path = os.path.join(dest_folder, "raw", "EBOOT")
    data = []
    for root, dir, files in os.walk(eboot_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f))
    data = replace_newlines(data)
    eboot_trans = os.path.join(dest_folder, "eboot_trans.json")
    with open(eboot_trans, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    # Combine the EVS translations
    evs_path = os.path.join(dest_folder, "raw", "EVS")
    data = []
    for root, dir, files in os.walk(evs_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f))
    data = replace_newlines(data)
    evs_trans = os.path.join(dest_folder, "evs_trans.json")
    with open(evs_trans, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
