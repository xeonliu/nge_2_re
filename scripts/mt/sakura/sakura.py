import re
import openai
from typing import Any, Dict, Optional


class TranslationModel:
    def __init__(self, version: str, api_base: str, model: str = "gpt-3.5-turbo"):
        self.version = version
        self.model = model
        openai.api_base = api_base
        openai.api_key = ""

    async def create_chat_completions(
        self,
        text: str,
        glossary: Dict[str, str],
        prev_text: str,
        signal: Optional[Any] = None,
        has_degradation: bool = False,
    ):
        messages = []

        def system(content: str):
            messages.append({"role": "system", "content": content})

        def user(content: str):
            messages.append({"role": "user", "content": content})

        def assistant(content: str):
            messages.append({"role": "assistant", "content": content})

        # 全角数字转换成半角数字
        text = re.sub(
            r"[\uff10-\uff19]", lambda ch: chr(ord(ch.group(0)) - 0xFEE0), text
        )

        if self.version == "1.0":
            system(
                "你是一个轻小说翻译模型，可以流畅通顺地以日本轻小说的风格将日文翻译成简体中文，并联系上下文正确使用人称代词，不擅自添加原文中没有的代词。"
            )
            if prev_text:
                assistant(prev_text)

            if len(glossary) == 0:
                user(f"将下面的日文文本翻译成中文：{text}")
            else:
                glossary_hint = "\n".join(
                    [f"{word_jp}->{word_zh}" for word_jp, word_zh in glossary.items()]
                )
                user(
                    f"根据以下术语表（可以为空）：\n{glossary_hint}\n"
                    f"将下面的日文文本根据对应关系和备注翻译成中文：{text}"
                )

        max_new_token = max(int(len(text) * 1.7), 100)
        completion = await openai.ChatCompletion.acreate(
            model=self.model,
            messages=messages,
            temperature=0.1,
            top_p=0.3,
            max_tokens=max_new_token,
            frequency_penalty=0.2 if has_degradation else 0.0,
        )

        return {
            "text": completion.choices[0].message.content,
            "has_degradation": completion.usage.completion_tokens >= max_new_token,
        }


# 示例用法
if __name__ == "__main__":
    import asyncio

    async def main():
        api_base = "http://localhost:9999/v1"
        model = ""
        model = TranslationModel(version="1.0", api_base=api_base, model=model)

        text = "これはテストです。"
        glossary = {"テスト": "测试"}
        prev_text = "这是之前的上下文内容。"
        result = await model.create_chat_completions(text, glossary, prev_text)
        print(result)

    asyncio.run(main())
