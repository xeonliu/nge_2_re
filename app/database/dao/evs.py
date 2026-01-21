"""
Persist EVSWrapper
"""

import hashlib
import logging
from tqdm import tqdm

from ..db import get_db
from app.parser import tools

from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.translation import Translation

logger = logging.getLogger(__name__)


class EVSDao:
    def save(hgar_file_id: int, evs_file: tools.EvsWrapper, db=None):
        """
        保存 EVS 条目到数据库
        
        Args:
            hgar_file_id: HGAR 文件 ID
            evs_file: EVS 包装器对象
            db: 可选的数据库会话，用于批量操作（避免重复创建会话）
        """
        # 如果没有提供 db 会话，创建新的
        if db is None:
            with next(get_db()) as db:
                EVSDao._save_with_session(hgar_file_id, evs_file, db)
        else:
            EVSDao._save_with_session(hgar_file_id, evs_file, db)
    
    @staticmethod
    def _save_with_session(hgar_file_id: int, evs_file: tools.EvsWrapper, db):
        """
        使用给定的数据库会话保存 EVS 数据（内部方法）
        """
        # 批量收集数据
        sentence_objects = []
        evs_objects = []
        sentence_keys_seen = set()
        
        for type, params, content in tqdm(evs_file.entries, desc="Processing EVS entries", unit="entry"):
            logger.debug("evs %s %s %s", type, params, content)
            
            # Entry Content
            if content is None or len(content) == 0:
                evs_objects.append(EVSEntry(
                    type=type,
                    param=params,
                    sentence_key=None,
                    hgar_file_id=hgar_file_id,
                ))
                continue

            # Hash the content
            hash_object = hashlib.md5(content.encode())
            hashed_str = hash_object.hexdigest()

            # 检查是否已经在当前批次中处理过
            if hashed_str not in sentence_keys_seen:
                # 检查数据库中是否已存在（只查询一次）
                if db.query(Sentence).filter(Sentence.key == hashed_str).scalar() is None:
                    sentence_objects.append(Sentence(key=hashed_str, content=content))
                    logger.debug("Evs add: %s", hashed_str)
                sentence_keys_seen.add(hashed_str)

            evs_objects.append(EVSEntry(
                type=type,
                param=params,
                sentence_key=hashed_str,
                hgar_file_id=hgar_file_id,
            ))
        
        # 批量插入 Sentence（使用 add_all 而非 bulk_save_objects）
        if sentence_objects:
            db.add_all(sentence_objects)
        
        # 批量插入 EVS Entry
        if evs_objects:
            db.add_all(evs_objects)
        
        # 只在这里提交一次
        db.commit()

    def form_evs_wrapper(hgar_file_id: int) -> tools.EvsWrapper:
        with next(get_db()) as db:
            evs_entries = (
                db.query(EVSEntry)
                .filter(EVSEntry.hgar_file_id == hgar_file_id)
                .order_by(EVSEntry.id.asc())
                .all()
            )
            logger.debug("Loaded %d EVS entries for hgar_file_id=%s", len(evs_entries), hgar_file_id)
            evs = tools.EvsWrapper()
            for entry in tqdm(evs_entries, desc="Forming EVS wrapper", unit="entry"):
                if entry.sentence_key is None:
                    evs.add_entry(entry.type, entry.param, b"")
                    continue
                translation = (
                    db.query(Translation)
                    .filter(Translation.key == entry.sentence_key)
                    .first()
                )
                original = (
                    db.query(Sentence)
                    .filter(Sentence.key == entry.sentence_key)
                    .first()
                )
                content = original.content
                if translation:
                    content = translation.content
                logger.debug("EVS content: %s", content)
                evs.add_entry(entry.type, entry.param, content)
            return evs
