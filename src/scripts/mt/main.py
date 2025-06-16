import os
import json
import asyncio
from scripts.mt.sakura import TranslationModel
import argparse


async def main():
    # Add arguments
    parser = argparse.ArgumentParser(description="Translation Model")
    parser.add_argument(
        "--term_file",
        type=str,
        default="term.json",
        help="Term file for translation.",
    )
    parser.add_argument(
        "--source_file",
        type=str,
        help="Source file for translation.",
    )
    parser.add_argument(
        "--dest_file",
        type=str,
        help="Destination file for translation.",
    )
    args = parser.parse_args()
    term_file = args.term_file
    source_file = args.source_file
    dest_file = args.dest_file

    # TODO: Use Paru
    api_base = "https://sakura-share.one/v1"
    model = "sakura-14b-qwen2.5-v1.0-w8a8-int8-v2"
    model = TranslationModel(version="1.0", api_base=api_base, model=model)

    text = "これはテストです。"
    glossary = {"テスト": "测试"}
    prev_text = "这是之前的上下文内容。"
    result = await model.create_chat_completions(text, glossary, prev_text)
    print(result)

    with open(os.path.join(term_file), "r", encoding="utf-8") as f:
        glossary: dict = {}
        data = json.load(f)
        for elem in data:
            glossary[elem["term"]] = elem["translation"]

    print(glossary)

    with open(os.path.join(source_file), "r", encoding="utf-8") as f:
        data = json.load(f)
        prev_text = None
        # Save
        results = []
        # Translate
        for elem in data:
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
            # prev_text = elem["original"]
            prev_text = None

            results.append(elem)

            with open(os.path.join(dest_file), "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=4)


asyncio.run(main())
