import hashlib
import logging
from tqdm import tqdm

from ..db import get_db
from ..entity.text_entry import TextEntry
from ..entity.translation import Translation

logger = logging.getLogger(__name__)


class TextEntryDao:
    """
    TEXT 文件条目 DAO
    管理 f2tuto.bin, f2info.bin 等 TEXT 格式文件的文本
    """
    
    @staticmethod
    def save_text_file_with_session(db, filename: str, text_archive):
        """
        使用现有 session 保存 TEXT 文件
        如果文件已存在，会因唯一约束而报错
        """
        # 保存所有条目
        for entry_index, (entry_unknown, entry_string_idx) in enumerate(text_archive.entries):
            # 获取对应的字符串内容
            if entry_string_idx < len(text_archive.strings):
                unknown_first, unknown_second, string_content = text_archive.strings[entry_string_idx]
                
                # 创建数据库条目
                text_entry = TextEntry(
                    filename=filename,
                    original=string_content or "",
                    entry_unknown=entry_unknown or 0,
                    entry_index=entry_index,
                    string_index=entry_string_idx,
                    unknown_first=unknown_first or 0,
                    unknown_second=unknown_second or 0,
                    header_padding=text_archive.header_padding,
                    entry_padding=text_archive.entry_padding
                )
                db.add(text_entry)

    @staticmethod
    def save_text_file(filename: str, text_archive):
        """
        保存 TEXT 文件到数据库
        
        Args:
            filename: TEXT 文件名（如 f2info.bin）
            text_archive: TextArchive 对象，包含 entries 和 strings
        """
        with next(get_db()) as db:
            TextEntryDao.save_text_file_with_session(db, filename, text_archive)
            db.commit()
            logger.debug(f"  [TextEntry] Saved {len(text_archive.entries)} entries from {filename}")
    
    @staticmethod
    def get_text_entries_by_filename(filename: str):
        """
        获取指定文件的所有条目
        """
        with next(get_db()) as db:
            entries = db.query(TextEntry).filter(TextEntry.filename == filename).all()
            return entries
    
    @staticmethod
    def rebuild_text_archive(filename: str, text_archive):
        """
        从数据库重建 TextArchive（应用翻译）
        
        Args:
            filename: TEXT 文件名
            text_archive: 要填充的 TextArchive 对象
        """
        with next(get_db()) as db:
            # 获取所有条目，按原始条目顺序（id）
            db_entries = db.query(TextEntry).filter(TextEntry.filename == filename).order_by(TextEntry.id).all()
            
            if not db_entries:
                logger.debug(f"  [TextEntry] No entries found for {filename}")
                return
            
            # 恢复元数据
            if db_entries:
                text_archive.header_padding = db_entries[0].header_padding
                text_archive.entry_padding = db_entries[0].entry_padding
            
            # 构建字符串内容到字符串索引的映射
            # 这样可以实现多个条目共享同一个字符串
            # FIXME: 事实上不需要这样
            # 注意：需要同时考虑内容和 unknown_first/unknown_second，因为它们可能标识说话人/语音
            string_key_to_idx = {}
            text_archive.strings = []
            text_archive.entries = []
            
            for db_entry in db_entries:
                # 计算原始字符串的hash用于查询翻译
                hash_object = hashlib.md5(db_entry.original.encode())
                hashed_str = hash_object.hexdigest()
                
                # 使用 hash 查询翻译
                trans = db.query(Translation).filter(Translation.key == hashed_str).first()
                # FIXME: 这里最好统一
                translated_content = trans.content.replace("\\n", "\n") if trans and trans.content else db_entry.original
                
                if trans:
                    logger.debug("Translation Found: %s -> %s", db_entry.original, translated_content)
                
                # 创建唯一键：内容 + unknown_first + unknown_second
                # 这样可以确保只有内容和 unknown 值都相同的字符串才会被重用
                string_key = (translated_content, db_entry.unknown_first, db_entry.unknown_second)
                
                # 检查这个字符串（包括 unknown 值）是否已经存在
                if string_key not in string_key_to_idx:
                    # 新字符串，添加到列表
                    string_idx = len(text_archive.strings)
                    text_archive.strings.append((
                        db_entry.unknown_first,
                        db_entry.unknown_second,
                        translated_content
                    ))
                    string_key_to_idx[string_key] = string_idx
                else:
                    # 重用已存在的字符串（内容和 unknown 值都相同）
                    string_idx = string_key_to_idx[string_key]
                
                # 添加条目，使用保存的 entry_unknown
                text_archive.entries.append((
                    db_entry.entry_unknown,
                    string_idx
                ))
            
            logger.debug(f"  [TextEntry] Rebuilt {len(text_archive.entries)} entries with {len(text_archive.strings)} strings for {filename}")
    
    @staticmethod
    def export_text_translations(filename: str, output_path: str):
        """
        导出 TEXT 文件的翻译为 JSON（Paratranz 格式）
        """
        import json
        
        with next(get_db()) as db:
            entries = db.query(TextEntry).filter(TextEntry.filename == filename).all()
            
            result = []
            for entry in tqdm(entries, desc="Exporting text entries", unit="entry"):
                # 计算原始字符串的hash用于查询翻译
                hash_object = hashlib.md5(entry.original.encode())
                hashed_str = hash_object.hexdigest()
                
                # 使用 hash 查询翻译
                trans = db.query(Translation).filter(Translation.key == hashed_str).first()
                result.append({
                    "key": entry.original,
                    "original": entry.original,
                    "translation": trans.content if trans else "",
                    "context": f"File: {filename}, Index: {entry.string_index}"
                })
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=4, ensure_ascii=False)
            
            logger.debug(f"  [TextEntry] Exported {len(result)} entries to {output_path}")
    
    @staticmethod
    def import_text_translations(json_path: str):
        """
        从 Paratranz JSON 导入翻译
        """
        import json
        
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        with next(get_db()) as db:
            count = 0
            for item in tqdm(data, desc="Importing translations", unit="entry"):
                original_key = item.get("key")
                translation = item.get("translation")
                
                if original_key and translation:
                    # 对原始内容进行 hash，用于存储翻译
                    hash_object = hashlib.md5(original_key.encode())
                    hashed_str = hash_object.hexdigest()
                    
                    # 检查是否存在
                    trans = db.query(Translation).filter(Translation.key == hashed_str).first()
                    if trans:
                        trans.content = translation
                    else:
                        trans = Translation(key=hashed_str, content=translation)
                        db.add(trans)
                    count += 1
            
            db.commit()
            logger.debug(f"  [TextEntry] Imported {count} translations from {json_path}")
