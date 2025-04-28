# 使用正则表达式匹配%s之类的字符串
import re
import os
import json


# 寻找字符串中的所有特殊字符，并以列表返回
def find_special_characters(s) -> dict[str, int]:
    # 匹配 %s, %d, %f, %x, %X, %o, %e, %E, %g, %G
    pattern = r"%[0-9]*[a-zA-Z]+"
    # 匹配 $s, $d, $f, $x, $X, $o, $e, $E, $g, $G
    pattern += r"|\$[0-9]*[a-zA-Z]+"
    matches = re.findall(pattern, s)
    # 生成键值对，统计每个字符的出现次数
    result = {}
    for match in matches:
        result[match] = result.get(match, 0) + 1
    return result


# 保证字符串中的元素内容和个数一致
def match_exist_in_string(matches: dict[str, int], string) -> KeyError|None:
    matches_in_str = find_special_characters(string)
    # print(f"Matches in string: {matches_in_str}")
    # 检查匹配的元素是否在字符串中,且每种个数一直
    for key, value in matches.items():
        if key not in matches_in_str or matches_in_str[key] != value:
            raise ValueError(
                f"Mismatch: {key} in matches is {value}, but in string is {matches_in_str.get(key, 0)}"
            )


if __name__ == "__main__":
    # # 测试字符串
    # test_string = "This is a test string with %s and $d %s."
    # # 匹配特殊字符
    # matches = find_special_characters(test_string)
    # print(f"Matches: {matches}")

    # # 测试字符串
    # test_string2 = "This is a test string with %s and $d."
    # # 检查是否存在
    # exists = match_exist_in_string(matches, test_string2)
    # print(f"Exists: {exists}")

    # 打开翻译文件，进行检查，统计出错，打印到标准输出
    # 读取命令行参数，包括翻译文件
    import sys
    if len(sys.argv) < 2:
        print("Usage: python check.py <translation_file>")
        sys.exit(1)
    translation_file = sys.argv[1]
    # 读取翻译文件
    with open(translation_file, "r", encoding="utf-8") as f:
        translation_data = json.load(f)
    errors = 0
    # 检查翻译文件中的每个字符
    for elem in translation_data:
        if "original" not in elem or "translation" not in elem:
            print("Error: Missing original or translation key")
            continue
        original = elem["original"]
        translation = elem["translation"]
        # 检查翻译文件中的每个字符
        try:
            matches = find_special_characters(original)
            match_exist_in_string(matches, translation)
        except ValueError as e:
            print(f"Error: {e}\nID: {elem['key']}")
            print(f"Original: {original}\nTranslation: {translation}\n\n")
            errors += 1
            continue
    print(f"Total errors: {errors}")
    
    
