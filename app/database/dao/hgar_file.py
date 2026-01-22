"""
Obtain a sentence with or without translation from the database.
"""

from ..db import get_db
from app.parser import tools
import logging
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Entities
from ..entity.hgar_file import HgarFile
from ..entity.raw import Raw
from ..entity.hgpt import Hgpt

from .evs import EVSDao
from .hgpt import HgptDao

logger = logging.getLogger(__name__)


class HGARFileDao:
    @staticmethod
    def save(hgar_id: int, hgar_files: list[tools.HGArchiveFile]):
        """
        保存 HGAR 文件列表到数据库
        主要处理 EVS 和 HGPT 文件的特殊存储需求
        其余文件作为 Raw 存储
        Args:
            hgar_id: 关联的 HGAR ID
            hgar_files: 要保存的 HGAR 文件列表
        """
        import zlib
        import struct
        
        # 使用单个数据库会话进行批量操作
        with next(get_db()) as db:
            # 第一阶段：预处理所有文件，收集数据
            processed_files = []
            hgpt_cache = {}  # 缓存当前批次中的 hgpt_key，避免重复处理
            
            for file in tqdm(hgar_files, desc="Processing files", unit="file"):
                # FIXME: Remove decode
                short_name: str = file.short_name.decode("ascii").rstrip(" \t\r\n\0")
                
                content = file.content
                
                # 检查文件是否压缩（通过 encoded_identifier 的最高位判断）
                is_compressed = ((file.encoded_identifier >> 31) == 1) if file.encoded_identifier else False
                
                # 如果文件是压缩的，先解压
                if is_compressed:
                    try:
                        # 压缩格式：size(4 bytes) + compressed_data (without zlib header/trailer)
                        original_size = struct.unpack('<I', content[:4])[0]
                        compressed_data = content[4:]
                        
                        # 解压时使用 -15 (raw deflate without header)
                        decompressed = zlib.decompress(compressed_data, -15)
                        logger.debug("  [DECOMPRESS] %s: %d → %d bytes", short_name, len(compressed_data), len(decompressed))
                        content = decompressed
                    except Exception as e:
                        logger.warning("  [DECOMPRESS ERROR] %s: %s", short_name, e)
                        # 如果解压失败，继续使用原始内容
                        content = content[4:]  # 至少跳过 size 字段
                
                # 处理文件内容，获取可能的 hgpt_key
                hgpt_key = None
                evs_wrapper = None
                
                if short_name.endswith(".evs"):
                    evs_wrapper = tools.EvsWrapper()
                    evs_wrapper.open_bytes(content)
                    logger.debug("  [EVS] %s", short_name)
                elif short_name.endswith(".zpt") or short_name.endswith(".hpt"):
                    # 计算 hash 来去重
                    import hashlib
                    hash_object = hashlib.md5(content)
                    hashed_key = hash_object.hexdigest()
                    
                    # 检查本地缓存
                    if hashed_key not in hgpt_cache:
                        # 保存 HGPT 到数据库（去重），使用当前 db 会话
                        logger.debug("  [HPT] %s", short_name)
                        hgpt_key = HgptDao.save(hgpt_data=content, db=db)
                        hgpt_cache[hashed_key] = hgpt_key
                    else:
                        hgpt_key = hgpt_cache[hashed_key]
                        logger.debug("  [HPT] %s (cached)", short_name)
                
                processed_files.append({
                    'file': file,
                    'short_name': short_name,
                    'content': content,
                    'hgpt_key': hgpt_key,
                    'evs_wrapper': evs_wrapper,
                })
            
            # 第二阶段：批量插入 HgarFile 记录
            hgar_file_objects = []
            for data in tqdm(processed_files, desc="Creating HgarFile records", unit="file"):
                file = data['file']
                hgar_file = HgarFile(
                    hgar_id=hgar_id,
                    short_name=data['short_name'],
                    long_name=file.long_name,
                    file_size=len(data['content']),
                    compressed_size=file.size if hasattr(file, 'size') else None,
                    encoded_identifier=file.encoded_identifier,
                    unknown_first=file.unknown_first,
                    unknown_last=file.unknown_last,
                    hgpt_key=data['hgpt_key'],  # 关联 HGPT
                )
                hgar_file_objects.append(hgar_file)
            
            # 使用 add_all 批量添加（保持对象在会话中）
            db.add_all(hgar_file_objects)
            db.flush()  # flush 来获取生成的 ID，但不提交事务
            
            # 第三阶段：批量保存文件内容（EVS、Raw）
            raw_objects = []
            evs_data = []
            
            for i, data in enumerate(tqdm(processed_files, desc="Saving file contents", unit="file")):
                hgar_file = hgar_file_objects[i]
                short_name = data['short_name']
                content = data['content']
                evs_wrapper = data['evs_wrapper']
                
                if short_name.endswith(".evs"):
                    # 收集 EVS 数据，稍后批量处理
                    evs_data.append((hgar_file.id, evs_wrapper))
                elif short_name.endswith(".hpt") or short_name.endswith(".zpt"):
                    # HGPT 已经通过 hgpt_key 关联，无需额外操作
                    pass
                else:
                    # 收集 Raw 对象，稍后批量插入
                    raw_objects.append(Raw(hgar_file_id=hgar_file.id, content=content))
            
            # 批量插入 Raw 数据
            if raw_objects:
                db.add_all(raw_objects)
            
            # 批量保存 EVS 数据（使用优化后的 EVSDao）
            for hgar_file_id, evs_wrapper in evs_data:
                EVSDao.save(hgar_file_id, evs_wrapper, db)
            
            # 最终提交所有数据
            db.commit()
            
        return hgar_files

    @staticmethod
    def _process_single_hgar_file(hgar_file, raw_map, hgpt_map, is_compressed):
        logger.debug("  Rebuilding: %s", hgar_file.short_name)

        # 获取原始内容
        short_name = hgar_file.short_name
        if short_name.endswith(".evs"):
            evs_wrapper: tools.EvsWrapper = EVSDao.form_evs_wrapper(hgar_file.id)
            content = evs_wrapper.save_bytes()
        elif short_name.endswith((".zpt", ".hpt")):
            if hgar_file.hgpt_key and hgar_file.hgpt_key in hgpt_map:
                hgpt = hgpt_map[hgar_file.hgpt_key]
                content = HgptDao._rebuild_from_png(hgpt) if hgpt.png_translated else hgpt.content
            elif hgar_file.id in raw_map:
                content = raw_map[hgar_file.id]
            else:
                logger.warning("    WARNING: No HGPT or Raw data for %s", hgar_file.short_name)
                return None
        else:
            if hgar_file.id in raw_map:
                content = raw_map[hgar_file.id]
            else:
                logger.warning("    WARNING: No Raw data for %s", hgar_file.short_name)
                return None

        # 按需要重新压缩（保持原有 zlib 设置和数据格式）
        if is_compressed:
            original_size = len(content)
            compressed = zlib.compress(content)
            compressed_content = compressed[2:-4]  # 去掉 zlib 头和校验，保持原格式
            content = struct.pack("<I", original_size) + compressed_content
            logger.debug("  [COMPRESS] %s: %d → %d bytes", short_name, original_size, len(compressed_content))

        return {
            "long_name": hgar_file.long_name,
            "short_name": short_name,
            "size": len(content),
            "encoded_identifier": hgar_file.encoded_identifier,
            "unknown_first": hgar_file.unknown_first,
            "unknown_last": hgar_file.unknown_last,
            "content": content,
        }

    @staticmethod
    def form(hgar_id: int) -> list[tools.HGArchiveFile]:
        with next(get_db()) as db:
            logger.debug("Form HGAR Files for %s", hgar_id)
            hgar_files = (
                db.query(HgarFile)
                .filter(HgarFile.hgar_id == hgar_id)
                .order_by(HgarFile.id.asc())
                .all()
            )
            
            # 预加载所有 Raw 数据（避免循环内多次查询）
            hgar_file_ids = [hf.id for hf in hgar_files]
            raw_map = {}
            if hgar_file_ids:
                raw_records = db.query(Raw).filter(Raw.hgar_file_id.in_(hgar_file_ids)).all()
                raw_map = {raw.hgar_file_id: raw.content for raw in raw_records}
            
            # 预加载所有 HGPT 数据
            hgpt_keys = {hf.hgpt_key for hf in hgar_files if hf.hgpt_key}
            hgpt_map = {}
            if hgpt_keys:
                hgpt_records = db.query(Hgpt).filter(Hgpt.key.in_(hgpt_keys)).all()
                hgpt_map = {h.key: h for h in hgpt_records}
            
            tasks = []
            for idx, hgar_file in enumerate(hgar_files):
                is_compressed = ((hgar_file.encoded_identifier >> 31) == 1) if hgar_file.encoded_identifier else False
                tasks.append((idx, hgar_file, is_compressed))

            results: list[tools.HGArchiveFile | None] = [None] * len(tasks)
            with ThreadPoolExecutor() as executor:
                future_to_idx = {
                    executor.submit(
                        HGARFileDao._process_single_hgar_file,
                        hgar_file,
                        raw_map,
                        hgpt_map,
                        is_compressed,
                    ): idx
                    for idx, hgar_file, is_compressed in tasks
                }

                for future in tqdm(as_completed(future_to_idx), total=len(future_to_idx), desc="Rebuilding HGAR files", unit="file"):
                    idx = future_to_idx[future]
                    result = future.result()
                    if result:
                        results[idx] = tools.HGArchiveFile(**result)

            return [res for res in results if res]
