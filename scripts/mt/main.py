import os, json
import asyncio
from .sakura.sakura import TranslationModel
from paratranz.download import dest_folder


async def main():
    api_base = "http://localhost:6006/v1"
    model = ""
    model = TranslationModel(version="1.0", api_base=api_base, model=model)

    text = "これはテストです。"
    glossary = {"テスト": "测试"}
    prev_text = "这是之前的上下文内容。"
    result = await model.create_chat_completions(text, glossary, prev_text)
    print(result)

    with open(os.path.join(dest_folder, "term.json"), "r", encoding="utf-8") as f:
        glossary: dict = {}
        data = json.load(f)
        for elem in data:
            glossary[elem["term"]] = elem["translation"]

    print(glossary)

    with open(os.path.join(dest_folder, "eboot_trans.json"), "r", encoding="utf-8") as f:
        data = json.load(f)
        prev_text = ""
        # Save
        results = []
        # Translate
        # found = False
        for elem in data:
            # if elem["key"] == "-3119569334078361786":
            #     found = True
            # if not found:
            #     continue
            # # Skip until key == -3119569334078361786
            result = await model.create_chat_completions(
                elem["original"], glossary, prev_text
            )
            has_degradation = result["has_degradation"]

            count = 0
            while has_degradation:
                result = await model.create_chat_completions(
                    elem["original"], glossary, prev_text, has_degradation=True
                )
                has_degradation = result["has_degradation"]
                count += 1
                if count > 3:
                    break

            elem["translated"] = result["text"]
            print(elem["translation"])
            print(elem["original"], "->", elem["translated"])
            prev_text = elem["original"]

            results.append(elem)
            with open(
                os.path.join(dest_folder, "ebbb.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(results, f, ensure_ascii=False, indent=4)


asyncio.run(main())
