"""
Check EBOOT Translation Size Limit
Check EVS Translation Size Limit
"""

import os
from tools.common import to_eva_sjis
from tools.evs import CONTENT_BYTE_LIMIT
from .download import dest_folder


def check_eboot(data):
    warn = []
    error = []
    for elem in data:
        original_bytes = to_eva_sjis(elem["original"])
        try:
            translation_bytes = to_eva_sjis(elem["translation"])
        except Exception as e:
            elem["info"] = "ERROR: " + str(e)
            error.append(elem)
            continue
        diff = len(translation_bytes) - len(original_bytes)
        if diff in range(1, 5):
            elem["info"] = "WARN: " + str(diff) + " bytes."
            warn.append(elem)
        elif diff > 4:
            elem["info"] = "ERROR: " + str(diff) + " bytes."
            error.append(elem)
    return warn, error


def check_evs(data):
    # 编码错误
    encoding_error = []
    # 换行符缺失
    paging_error = []
    # 转义字符缺失
    escape_error = []
    for elem in data:
        original = elem["original"]
        translation = elem["translation"]
        try:
            to_eva_sjis(translation)
        except Exception as e:
            elem["info"] = "ERROR: " + str(e)
            encoding_error.append(elem)
            continue
        split_contents = translation.split("▽")
        for content in split_contents:
            raw_content = to_eva_sjis(content)
            raw_split_length = len(
                raw_content.replace(b" ", b"").replace(b"\n", b"") + to_eva_sjis("▽")
            )
            if raw_split_length >= CONTENT_BYTE_LIMIT:
                elem["info"] = (
                    "ERROR: Paging Error, content: "
                    + content
                    + " length: "
                    + str(raw_split_length)
                    + " bytes."
                )
                paging_error.append(elem)
        if "$" in original and "$" not in translation:
            elem["info"] = "ERROR: Escape Error, NO '$'"
            escape_error.append(elem)
        if "%" in original and "%" not in translation:
            elem["info"] = "ERROR: Escape Error, NO '%'"
            escape_error.append(elem)
    return encoding_error, paging_error, escape_error


def rm_orig(data):
    for elem in data:
        if "original" in elem:
            del elem["original"]
        if "context" in elem:
            del elem["context"]
    return data


if __name__ == "__main__":
    import json

    with open(
        os.path.join(dest_folder, "eboot_trans.json"), "r", encoding="utf-8"
    ) as f:
        data = json.load(f)
        warn, error = check_eboot(data)

        warn = rm_orig(warn)
        error = rm_orig(error)
        with open(
            os.path.join(dest_folder, "eboot_warn.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(warn, f, ensure_ascii=False, indent=4)
        with open(
            os.path.join(dest_folder, "eboot_error.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(error, f, ensure_ascii=False, indent=4)

        print("EBOOT Total: ", len(data))
        print("EBOOT Warn: ", len(warn))
        print("EBOOT Error: ", len(error))

    with open(os.path.join(dest_folder, "evs_trans.json"), "r", encoding="utf-8") as f:
        data = json.load(f)
        # Check
        encoding_error, paging_error, escape_error = check_evs(data)
        encoding_error = rm_orig(encoding_error)
        paging_error = rm_orig(paging_error)
        escape_error = rm_orig(escape_error)
        
        with open(
            os.path.join(dest_folder, "evs_encoding_error.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(encoding_error, f, ensure_ascii=False, indent=4)
        with open(
            os.path.join(dest_folder, "evs_paging_error.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(paging_error, f, ensure_ascii=False, indent=4)
        with open(
            os.path.join(dest_folder, "evs_escape_error.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(escape_error, f, ensure_ascii=False, indent=4)

        print("EVS Total: ", len(data))
        print("EVS Encoding Error: ", len(encoding_error))
        print("EVS Paging Error: ", len(paging_error))
        print("EVS Escape Error: ", len(escape_error))

    print("Done!")
