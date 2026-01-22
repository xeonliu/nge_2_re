#!/usr/bin/env python3
"""
批量翻译 JSONL 文件
将英文文本翻译成中文，并添加 translation 字段
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any
from openai import OpenAI
from pydantic import BaseModel

# 配置
BATCH_SIZE = 5  # 每批翻译的条目数
INPUT_FILE = "imtext_stage0.json"
OUTPUT_FILE = "imtext_stage0_translated.json"
API_KEY = os.getenv("OPENAI_API_KEY")  # 从环境变量读取
API_BASE = os.getenv("OPENAI_API_BASE")  # API Base URL，可选
GLOSSARY_FILE = "terms-10882.json"


class TranslationItem(BaseModel):
    """单条翻译结果"""
    id: int
    translation: str


class TranslationBatch(BaseModel):
    """批量翻译结果"""
    translations: List[TranslationItem]


def load_glossary_terms(file_path: str) -> List[Dict[str, Any]]:
    """加载术语表，仅保留必要字段以控制提示长度"""
    raw_terms = load_json(file_path)
    glossary = []
    for entry in raw_terms:
        translation = entry.get("translation")
        terms = []
        if entry.get("term"):
            terms.append(entry["term"])
        variants = entry.get("variants") or []
        for variant in variants:
            if variant:
                terms.append(variant)
        if not translation or not terms:
            continue
        glossary.append({
            "terms": terms,
            "translation": translation,
            "caseSensitive": bool(entry.get("caseSensitive", False))
        })
    return glossary


def load_json(file_path: str) -> List[Dict[str, Any]]:
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data


def save_json(data: List[Dict[str, Any]], file_path: str):
    """保存为 JSON 文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def translate_batch(client: OpenAI, items: List[Dict[str, Any]], glossary: List[Dict[str, Any]]) -> List[str]:
    """
    批量翻译一批文本
    
    Args:
        client: OpenAI 客户端
        items: 待翻译的条目列表
    
    Returns:
        翻译结果列表
    """
    # 构建翻译提示
    texts_to_translate = []
    for item in items:
        texts_to_translate.append({
            "id": item["id"],
            "text": item["original"]
        })
    
        glossary_prompt = ""
        if glossary:
                glossary_prompt = (
                        "请参考以下术语表，遇到术语或其变体时必须使用对应译名"
                        "（遵守 caseSensitive 标记）：\n"
                        f"{json.dumps(glossary, ensure_ascii=False, indent=2)}\n\n"
                )

        prompt = f"""请将以下英文文本翻译成简体中文。这些是游戏《新世纪福音战士》的对话文本。
请以轻小说的风格保持翻译的准确性和流畅性同时兼顾角色的语气，第二人称非特殊情况使用“你”，符合中文表达和标点习惯，如省略号使用“……” ，语气停顿使用逗号，引号使用直角引号「」。同时注意保留原有的$m, $n等特殊标记及其数目不变。

{glossary_prompt}待翻译文本：
{json.dumps(texts_to_translate, ensure_ascii=False, indent=2)}

请严格按照以下 JSON 格式返回翻译结果（不要包含任何其他文字说明）：
{{
    "translations": [
        {{"id": ID数字, "translation": "翻译内容"}},
        ...
    ]
}}"""

    try:
        completion = client.chat.completions.create(
            model="deepseek/deepseek-v3.1-terminus",
            messages=[
                {
                    "role": "system",
                    "content": "你是一个专业的游戏翻译专家，擅长将日文游戏文本翻译成简体中文。请严格按照 JSON 格式返回翻译结果。"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
        )
        
        # 调试：检查返回类型
        print(f"DEBUG - completion 类型: {type(completion)}")
        print(f"DEBUG - completion 内容: {completion}")
        
        # 获取回复内容
        if isinstance(completion, str):
            # 如果直接返回字符串，就用这个字符串
            content = completion
        else:
            # 标准 OpenAI 响应格式
            content = completion.choices[0].message.content
        
        # 尝试提取 JSON（处理可能的 markdown 代码块）
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        # 解析 JSON
        result_json = json.loads(content)
        result = TranslationBatch(**result_json)
        
        # 验证返回数量
        if len(result.translations) != len(items):
            raise ValueError(
                f"翻译数量不匹配！发送了 {len(items)} 条，收到了 {len(result.translations)} 条"
            )
        
        # 验证 ID 匹配
        for i, (item, trans) in enumerate(zip(items, result.translations)):
            if item["id"] != trans.id:
                raise ValueError(
                    f"第 {i+1} 条 ID 不匹配！期望 {item['id']}，得到 {trans.id}"
                )
        
        return [trans.translation for trans in result.translations]
        
    except Exception as e:
        print(f"翻译出错: {e}")
        raise


def main():
    """主函数"""
    # 检查 API Key
    if not API_KEY:
        print("错误: 请设置 OPENAI_API_KEY 环境变量")
        print("例如: export OPENAI_API_KEY='your-api-key'")
        return
    
    # 初始化 OpenAI 客户端
    client_kwargs = {"api_key": API_KEY}
    if API_BASE:
        client_kwargs["base_url"] = API_BASE
        print(f"使用自定义 API Base: {API_BASE}")
    
    client = OpenAI(**client_kwargs)

    glossary: List[Dict[str, Any]] = []
    if Path(GLOSSARY_FILE).exists():
        print(f"加载术语表 {GLOSSARY_FILE}...")
        glossary = load_glossary_terms(GLOSSARY_FILE)
        print(f"术语条目: {len(glossary)}")
    else:
        print(f"未找到术语表 {GLOSSARY_FILE}，将不使用术语提示")
    
    # 加载数据
    print(f"正在加载 {INPUT_FILE}...")
    data = load_json(INPUT_FILE)
    print(f"共加载 {len(data)} 条数据")
    
    # 检查是否已有翻译文件，如果有则从断点继续
    start_index = 0
    translated_data = []
    
    if Path(OUTPUT_FILE).exists():
        print(f"发现已存在的翻译文件 {OUTPUT_FILE}，从断点继续...")
        translated_data = load_json(OUTPUT_FILE)
        start_index = len(translated_data)
        print(f"已翻译 {start_index} 条，将从第 {start_index + 1} 条继续")
    
    # 分批翻译
    total = len(data)
    for i in range(start_index, total, BATCH_SIZE):
        batch = data[i:i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"\n正在翻译第 {batch_num}/{total_batches} 批 (第 {i+1}-{min(i+BATCH_SIZE, total)} 条)...")
        
        try:
            translations = translate_batch(client, batch, glossary)
            
            # 添加翻译字段
            for item, translation in zip(batch, translations):
                translated_item = item.copy()
                translated_item["translation"] = translation
                translated_item["stage"] = 1  # 标记为已翻译阶段
                translated_data.append(translated_item)
            
            # 每批次保存一次（防止中断丢失）
            save_json(translated_data, OUTPUT_FILE)
            print(f"✓ 完成，已保存到 {OUTPUT_FILE}")
            
        except Exception as e:
            print(f"✗ 批次翻译失败: {e}")
            print(f"已保存前 {len(translated_data)} 条翻译结果到 {OUTPUT_FILE}")
            print("您可以修复问题后重新运行脚本，将自动从断点继续")
            return
    
    print(f"\n🎉 全部翻译完成！")
    print(f"输入文件: {INPUT_FILE} ({len(data)} 条)")
    print(f"输出文件: {OUTPUT_FILE} ({len(translated_data)} 条)")


if __name__ == "__main__":
    main()
