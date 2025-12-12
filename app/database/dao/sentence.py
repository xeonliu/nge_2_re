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
    def save(sentence: Sentence):
        with next(get_db()) as db:
            db.add(sentence)
            db.commit()
            db.refresh(sentence)
            return sentence

    def export_sentence_entry(prefix: str):
        with next(get_db()) as db:
            subquery = (
                db.query(EVSEntry.sentence_key, func.min(EVSEntry.id).label("min_id"))
                .join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)
                .join(Hgar, HgarFile.hgar_id == Hgar.id)
                .filter(Hgar.name.like(f"{prefix}%"))
                .filter(EVSEntry.type == 1)
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
    
    def export_sentence_by_path(relative_path: str):
        """按照 relative_path 导出句子（用于非 event 目录）"""
        with next(get_db()) as db:
            subquery = (
                db.query(EVSEntry.sentence_key, func.min(EVSEntry.id).label("min_id"))
                .join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)
                .join(Hgar, HgarFile.hgar_id == Hgar.id)
                .filter(Hgar.relative_path == relative_path)
                .filter(EVSEntry.type == 1)
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
    
    def get_all_relative_paths():
        """获取所有不同的 relative_path"""
        with next(get_db()) as db:
            paths = db.query(Hgar.relative_path).distinct().all()
            return [path[0] for path in paths if path[0]]  # 过滤空字符串
