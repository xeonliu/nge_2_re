import os, json
import asyncio
import argparse
from .sakura.sakura import TranslationModel

async def main():
    parser = argparse.ArgumentParser(description="Translation script with input and output file options.")
    parser.add_argument("--term", required=True, help="Path to the term JSON file.")
    parser.add_argument("--input", required=True, help="Path to the input JSON file.")
    parser.add_argument("--output", required=True, help="Path to the output JSON file.")
    args = parser.parse_args()

    api_base = "https://sakura-share.one/v1"
    model = "sakura-14b-qwen2.5-v1.0-iq4xs"
    model = TranslationModel(version="1.0", api_base=api_base, model=model)

    text = "これはテストです。"
    glossary = {"テスト": "测试"}
    prev_text = "这是之前的上下文内容。"
    result = await model.create_chat_completions(text, glossary, prev_text)
    print(result)

    with open(args.term, "r", encoding="utf-8") as f:
        glossary: dict = {}
        data = json.load(f)
        for elem in data:
            glossary[elem["term"]] = elem["translation"]

    print(glossary)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
        prev_text = ""
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
            prev_text = elem["original"]

            results.append(elem)
            with open(
                args.output, "w", encoding="utf-8"
            ) as f:
                json.dump(results, f, ensure_ascii=False, indent=4)


asyncio.run(main())
