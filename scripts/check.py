# 使用正则表达式匹配%s之类的字符串
import re
import json
from tools.common import to_eva_sjis
from tools.evs import CONTENT_BYTE_LIMIT


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
def match_exist_in_string(matches: dict[str, int], string) -> KeyError | None:
    matches_in_str = find_special_characters(string)
    # print(f"Matches in string: {matches_in_str}")
    # 检查匹配的元素是否在字符串中,且每种个数一直
    for key, value in matches.items():
        if key not in matches_in_str or matches_in_str[key] != value:
            raise ValueError(
                f"Mismatch: {key} in matches is {value}, but in string is {matches_in_str.get(key, 0)}"
            )


def special_character_error(source: str, translation: str) -> KeyError | None:
    """
    检查翻译文件中的特殊字符是否匹配
    :param source: 原始字符串
    :param translation: 翻译字符串
    :return: None
    """
    # 寻找原始字符串中的特殊字符
    matches = find_special_characters(source)
    # 检查翻译字符串中是否存在这些特殊字符
    match_exist_in_string(matches, translation)


# TODO: Check EBOOT
def eboot_length_error(source: str, translation: str) -> KeyError | None:
    """
    检查翻译文件中的长度差异
    :param source: 原始字符串
    :param translation: 翻译字符串
    :return: None
    """
    original_bytes = to_eva_sjis(elem["original"])
    translation_bytes = to_eva_sjis(translation)
    diff = len(translation_bytes) - len(original_bytes)
    if diff in range(1, 5):
        raise ValueError(
            f"Warning: {str(diff)} bytes difference between original and translation"
        )
    elif diff > 4:
        raise ValueError(
            f"Error: {str(diff)} bytes difference between original and translation"
        )


def encoding_error(source: str, translation: str) -> KeyError | None:
    """
    检查翻译文件中的编码错误
    :param source: 原始字符串
    :param translation: 翻译字符串
    :return: None
    """
    try:
        to_eva_sjis(translation)
    except Exception as e:
        raise ValueError(f"Encoding Error: {str(e)}")


def paging_error(source: str, translation: str) -> KeyError | None:
    """
    检查翻译字符串中分页后是否超出限制
    :param source: 原始字符串
    :param translation: 翻译字符串
    :return: None
    """
    # 检查翻译字符串中是否存在分页符
    split_contents = translation.split("▽")
    for content in split_contents:
        raw_content = to_eva_sjis(content)
        raw_split_length = len(
            raw_content.replace(b" ", b"").replace(b"\n", b"") + to_eva_sjis("▽")
        )
        if raw_split_length >= CONTENT_BYTE_LIMIT:
            raise ValueError(
                f"Error: Paging Error, content: {content} length: {str(raw_split_length)} bytes."
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

    if len(sys.argv) < 4:
        print("Usage: python check.py <translation_file> <report_file> <type>")
        sys.exit(1)
    translation_file = sys.argv[1]
    report_file = sys.argv[2]
    type = sys.argv[3]
    # 读取翻译文件
    with open(translation_file, "r", encoding="utf-8") as f:
        translation_data = json.load(f)
    errors = []
    # 检查翻译文件中的每个字符
    for elem in translation_data:
        if "original" not in elem or "translation" not in elem:
            print("Error: Missing original or translation key")
            continue
        original = elem["original"]
        translation = elem["translation"]
        # 检查翻译文件中的每个字符
        try:
            special_character_error(original, translation)
            if type == "eboot":
                eboot_length_error(original, translation)
            else:
                encoding_error(original, translation)
                paging_error(original, translation)
        except ValueError as e:
            print(f"Error: {e}\nID: {elem['key']}")
            errors.append(
                {
                    "key": elem["key"],
                    "original": original,
                    "translation": translation,
                    "error": str(e),
                }
            )
            continue
    print(f"Total errors: {len(errors)}")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(errors, f, ensure_ascii=False, indent=4)
