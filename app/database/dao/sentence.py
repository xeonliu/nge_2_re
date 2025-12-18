"""
Obtain a sentence with or without translation from the database.
"""

from sqlalchemy import func
from ..db import get_db

# Entities
from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile


class SentenceDao:
    @staticmethod
    def save(sentence: Sentence):
        with next(get_db()) as db:
            db.add(sentence)
            db.commit()
            db.refresh(sentence)
            return sentence

    @staticmethod
    def export_sentence_entry(prefix: str):
        with next(get_db()) as db:
            # HAS_CONTENT_SECTION = (0x01, 0x8C, 0x8D, 0xA3, 0x8E, 0x95)
            # 包含文本内容的所有function类型：1(对话), 140(0x8C), 141(0x8D), 142(0x8E), 149(0x95), 163(0xA3)
            HAS_CONTENT_SECTION = (0x01, 0x8C, 0x8D, 0xA3, 0x8E, 0x95)
            subquery = (
                db.query(EVSEntry.sentence_key, func.min(EVSEntry.id).label("min_id"))
                .join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)
                .join(Hgar, HgarFile.hgar_id == Hgar.id)
                .filter(Hgar.name.like(f"{prefix}%"))
                .filter(EVSEntry.type.in_(HAS_CONTENT_SECTION))
                .group_by(EVSEntry.sentence_key)
                .subquery()
            )

            results = (
                db.query(Sentence, EVSEntry)
                .join(subquery, Sentence.key == subquery.c.sentence_key)
                .join(EVSEntry, EVSEntry.id == subquery.c.min_id)
                .order_by(Sentence.id)
                .all()
            )
            return results
    
    @staticmethod
    def export_sentence_by_path(relative_path: str):
        """按照 relative_path 导出句子（用于非 event 目录）"""
        with next(get_db()) as db:
            # HAS_CONTENT_SECTION = (0x01, 0x8C, 0x8D, 0xA3, 0x8E, 0x95)
            # 包含文本内容的所有function类型：1(对话), 140(0x8C), 141(0x8D), 142(0x8E), 149(0x95), 163(0xA3)
            HAS_CONTENT_SECTION = (0x01, 0x8C, 0x8D, 0xA3, 0x8E, 0x95)
            subquery = (
                db.query(EVSEntry.sentence_key, func.min(EVSEntry.id).label("min_id"))
                .join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)
                .join(Hgar, HgarFile.hgar_id == Hgar.id)
                .filter(Hgar.relative_path == relative_path)
                .filter(EVSEntry.type.in_(HAS_CONTENT_SECTION))
                .group_by(EVSEntry.sentence_key)
                .subquery()
            )

            results = (
                db.query(Sentence, EVSEntry)
                .join(subquery, Sentence.key == subquery.c.sentence_key)
                .join(EVSEntry, EVSEntry.id == subquery.c.min_id)
                .order_by(Sentence.id)
                .all()
            )
            return results
    
    @staticmethod
    def get_all_relative_paths():
        """获取所有不同的 relative_path"""
        with next(get_db()) as db:
            paths = db.query(Hgar.relative_path).distinct().all()
            return [path[0] for path in paths if path[0]]  # 过滤空字符串
