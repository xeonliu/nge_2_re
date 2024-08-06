import requests, csv
import argparse, json, os


def translate_text(text, target_lang, api_key):
    url = "https://api-free.deepl.com/v2/translate"
    params = {"auth_key": api_key, "text": text, "target_lang": target_lang}
    response = requests.post(url, data=params)
    if response.status_code == 200:
        result = response.json()
        return result["translations"][0]["text"]
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None


def read_csv(csv_path):
    kv_pairs = []
    with open(csv_path, mode="r", encoding="utf-8") as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            kv_pair = {}
            kv_pair["key"] = row[0]
            kv_pair["original"] = row[1]
            kv_pair["translation"] = row[2]
            kv_pair["context"] = row[3]
            print(kv_pair)
            kv_pairs.append(kv_pair)
    return kv_pairs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Translation")
    parser.add_argument("-c", "--csv", required=True)

    args = parser.parse_args()
    kv_pairs = read_csv(args.csv)
    api_key = os.getenv("DEEPL_API_KEY")
    if not api_key:
        raise ValueError("DEEPL_API_KEY环境变量未设置")
    target_language = "ZH"  # 目标语言代码，例如 "ZH" 表示中文

    for pair in kv_pairs:
        translated_text = translate_text(pair["original"], target_language, api_key)
        if translated_text:
            print(f"Translated text: {translated_text}")
            pair["translation"] = translated_text

    # 获取源文件的文件名（不带扩展名）
    base_name = os.path.splitext(args.csv)[0]
    # 生成新的文件名，添加 _trans.json 后缀
    new_file_name = base_name + "_trans.json"
    # 将修改后的 kv_pairs 保存到新的 JSON 文件中
    with open(new_file_name, "w", encoding="utf-8") as f:
        json.dump(kv_pairs, f, ensure_ascii=False, indent=4)
