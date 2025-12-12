import hashlib
import json
import os

from ..db import get_db
from ..entity.bind_entry import BindEntry
from ..entity.translation import Translation
from app.parser.tools import common


class BindDao:
    """
    BIND 归档文件 DAO
    管理 imtext.bin, btimtext.bin 等 BIND 格式文件
    """
    
    @staticmethod
    def save_bind_file(filename: str, bind_archive):
        """
        保存 BIND 文件到数据库
        
        BIND 文件中的每个条目都是独立的 TEXT 格式文件
        我们将它们解析并使用 TextEntryDao 保存
        
        Args:
            filename: BIND 文件名（如 imtext.bin）
            bind_archive: BindArchive 对象，包含 entries
        """
        from app.parser.tools import text as text_module
        from ..dao.text_entry import TextEntryDao
        from ..entity.text_entry import TextEntry
        
        with next(get_db()) as db:
            # 清除该文件的旧条目
            db.query(BindEntry).filter(BindEntry.filename == filename).delete()
            # 清除该文件的旧 TEXT 条目
            db.query(TextEntry).filter(TextEntry.filename.like(f"{filename}#%")).delete(synchronize_session=False)
            
            text_count = 0
            binary_count = 0
            
            # 保存所有条目
            for entry_index, entry in enumerate(bind_archive.entries):
                # 无论是否是 TEXT，都保存到 BindEntry 作为备份和结构参考
                bind_entry = BindEntry(
                    filename=filename,
                    entry_index=entry_index,
                    content=entry.content,
                    text_content=None,
                    size_byte_size=bind_archive.size_byte_size,
                    block_size=bind_archive.block_size
                )
                db.add(bind_entry)
                
                # 检查是否是 TEXT 格式
                if entry.content.startswith(b'TEXT'):
                    # 这是一个 TEXT 格式文件，使用 TextArchive 解析
                    try:
                        text_archive = text_module.TextArchive()
                        text_archive.open_bytes(entry.content)
                        
                        # 使用 TextEntryDao 保存，filename 使用 "bind_filename#index" 格式
                        sub_filename = f"{filename}#{entry_index}"
                        # 使用 save_text_file_with_session 避免关闭 session
                        TextEntryDao.save_text_file_with_session(db, sub_filename, text_archive)
                        text_count += 1
                    except Exception as e:
                        print(f"  [WARNING] Failed to parse TEXT at entry {entry_index}: {e}")
                        # 解析失败，仅保留 BindEntry
                        binary_count += 1
                else:
                    # 不是 TEXT 格式，仅保留 BindEntry
                    binary_count += 1
            
            db.commit()
            print(f"  [BindEntry] Saved {len(bind_archive.entries)} entries from {filename}")
            print(f"  [BindEntry]   - {text_count} TEXT files (stored in TextEntry)")
            print(f"  [BindEntry]   - {binary_count} binary/failed entries (stored in BindEntry)")
    
    @staticmethod
    def get_bind_entries_by_filename(filename: str):
        """
        获取指定文件的所有条目
        """
        with next(get_db()) as db:
            entries = db.query(BindEntry).filter(
                BindEntry.filename == filename
            ).order_by(BindEntry.entry_index).all()
            return entries
    
    @staticmethod
    def rebuild_bind_archive(filename: str, bind_archive):
        """
        从数据库重建 BindArchive（应用翻译）
        
        对于 TEXT 格式的条目，从 TextEntry 表重建
        对于二进制条目，从 BindEntry 表重建
        
        Args:
            filename: BIND 文件名
            bind_archive: 要填充的 BindArchive 对象
        """
        from app.parser.tools import text as text_module
        from ..dao.text_entry import TextEntryDao
        from ..entity.text_entry import TextEntry
        
        with next(get_db()) as db:
            # 获取所有条目（现在 BindEntry 包含所有条目）
            all_entries = db.query(BindEntry).filter(
                BindEntry.filename == filename
            ).order_by(BindEntry.entry_index).all()
            
            if not all_entries:
                print(f"  [BindEntry] No entries found for {filename}")
                return
            
            # 恢复元数据
            bind_archive.size_byte_size = all_entries[0].size_byte_size
            bind_archive.block_size = all_entries[0].block_size
            
            # 获取所有有数据的 TEXT 条目文件名
            text_entries_filenames = set(
                f[0] for f in db.query(TextEntry.filename).filter(
                    TextEntry.filename.like(f"{filename}#%")
                ).distinct().all()
            )
            
            # 重建
            bind_archive.entries = []
            for entry in all_entries:
                sub_filename = f"{filename}#{entry.entry_index}"
                
                if sub_filename in text_entries_filenames:
                    # TEXT 条目：使用 TextEntryDao 重建
                    text_archive = text_module.TextArchive()
                    TextEntryDao.rebuild_text_archive(sub_filename, text_archive)
                    
                    # 序列化 TEXT
                    content = text_archive.serialize()
                    bind_archive.add_entry(content)
                else:
                    # 二进制条目或空 TEXT 条目：直接使用原始内容
                    bind_archive.add_entry(entry.content)
            
            print(f"  [BindEntry] Rebuilt {len(bind_archive.entries)} entries for {filename}")
    
    @staticmethod
    def export_bind_translations(filename: str, output_path: str):
        """
        导出 BIND 文件的翻译为 JSON（Paratranz 格式）
        
        BIND 文件中的 TEXT 条目已经通过 TextEntryDao 保存
        这里只需要导出那些 TEXT 条目的翻译
        """
        from ..dao.text_entry import TextEntryDao
        from ..entity.text_entry import TextEntry
        
        with next(get_db()) as db:
            # 获取所有 TEXT 条目（filename 格式为 "bind_filename#index"）
            text_entries = db.query(TextEntry.filename).filter(
                TextEntry.filename.like(f"{filename}#%")
            ).distinct().order_by(TextEntry.filename).all()
            
            if not text_entries:
                print(f"  [BindEntry] No TEXT entries found for {filename}")
                return
            
            # 使用 TextEntryDao 导出每个 TEXT 的翻译
            import tempfile
            all_translations = []
            
            for (text_filename,) in text_entries:
                # 创建临时文件
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                    tmp_path = tmp.name
                
                try:
                    # 导出这个 TEXT 的翻译
                    TextEntryDao.export_text_translations(text_filename, tmp_path)
                    
                    # 读取并合并到总结果
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        translations = json.load(f)
                        all_translations.extend(translations)
                finally:
                    os.unlink(tmp_path)
            
            # 保存合并后的结果
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(all_translations, f, indent=4, ensure_ascii=False)
            
            print(f"  [BindEntry] Exported {len(all_translations)} text entries to {output_path}")
    
    @staticmethod
    def get_all_bind_filenames():
        """
        获取所有已导入的 BIND 文件名
        """
        with next(get_db()) as db:
            filenames = db.query(BindEntry.filename).distinct().all()
            return [name for (name,) in filenames]
