import requests
import zipfile
import os
import json


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


if __name__ == "__main__":
    project_id = 10882  # 替换为你的项目ID
    url = f"https://paratranz.cn/api/projects/{project_id}/artifacts/download"
    dest_folder = "downloads"

    auth_key = os.getenv("AUTH_KEY")
    if not auth_key:
        raise ValueError("AUTH_KEY环境变量未设置")

    # Download files from paratranz.
    zip_path = download_file(url, dest_folder, auth_key)
    if zip_path:
        # Unzip them
        unzip_file(zip_path, dest_folder)
        print(f"Files have been downloaded and extracted to {dest_folder}")

    # Combine all the EBOOT Translations.
    eboot_path = os.path.join(dest_folder, "utf8", "eboot")
    data = []
    for root, dir, files in os.walk(eboot_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8") as f:
                data.extend(json.load(f))
    eboot_trans = os.path.join(dest_folder, "eboot_trans.json")
    with open(eboot_trans, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    # Combine the EVS translations
    # TODO
