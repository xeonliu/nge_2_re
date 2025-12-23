"""
Obtain a sentence with or without translation from the database.
"""

from ..db import get_db
from app.parser import tools
import logging
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
        for file in tqdm(hgar_files, desc="Saving HGAR files", unit="file"):
            with next(get_db()) as db:
                # FIXME: Remove decode
                short_name: str = file.short_name.decode("ascii").rstrip(" \t\r\n\0")
                
                content = file.content
                
                # 检查文件是否压缩（通过 encoded_identifier 的最高位判断）
                is_compressed = ((file.encoded_identifier >> 31) == 1) if file.encoded_identifier else False
                
                # 如果文件是压缩的，先解压
                if is_compressed:
                    import zlib
                    import struct
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
                if short_name.endswith(".evs"):
                    evs_wrapper = tools.EvsWrapper()
                    evs_wrapper.open_bytes(content)
                    logger.debug("  [EVS] %s", short_name)
                elif short_name.endswith(".zpt") or short_name.endswith(".hpt"):
                    # 保存 HGPT 到数据库（去重）
                    logger.debug("  [HPT] %s", short_name)
                    hgpt_key = HgptDao.save(hgpt_data=content)
                
                # 创建 HgarFile 记录
                hgar_file = HgarFile(
                    hgar_id=hgar_id,
                    short_name=short_name,
                    long_name=file.long_name,
                    file_size=len(content),
                    compressed_size=file.size if hasattr(file, 'size') else None,
                    encoded_identifier=file.encoded_identifier,
                    unknown_first=file.unknown_first,
                    unknown_last=file.unknown_last,
                    hgpt_key=hgpt_key,  # 关联 HGPT
                )
                db.add(hgar_file)
                db.commit()

                # 持久化文件内容
                if short_name.endswith(".evs"):
                    EVSDao.save(hgar_file.id, evs_wrapper)
                elif short_name.endswith(".hpt") or short_name.endswith(".zpt"):
                    # HGPT 已经通过 hgpt_key 关联，无需额外操作
                    pass
                else:
                    raw = Raw(hgar_file_id=hgar_file.id, content=content)
                    db.add(raw)
                    db.commit()
        return hgar_files

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
            hg_archive_files = []
            for hgar_file in tqdm(hgar_files, desc="Rebuilding HGAR files", unit="file"):
                logger.debug("  Rebuilding: %s", hgar_file.short_name)
                
                # 根据文件类型重建内容
                if hgar_file.short_name.endswith(".evs"):
                    # 重建 EVS 文件
                    evs_wrapper: tools.EvsWrapper = EVSDao.form_evs_wrapper(
                        hgar_file.id
                    )
                    content = evs_wrapper.save_bytes()
                    
                elif hgar_file.short_name.endswith(".zpt") or hgar_file.short_name.endswith(".hpt"):
                    # 重建 HGPT 文件
                    if hgar_file.hgpt_key:
                        content = HgptDao.get_hgpt_data(hgar_file.hgpt_key)
                    else:
                        # 如果没有关联 HGPT，从 Raw 读取
                        raw = db.query(Raw).filter(Raw.hgar_file_id == hgar_file.id).first()
                        if raw:
                            content = raw.content
                        else:
                            logger.warning("    WARNING: No HGPT or Raw data for %s", hgar_file.short_name)
                            continue
                            
                else:
                    # 其他文件类型，从 Raw 表读取
                    raw = db.query(Raw).filter(Raw.hgar_file_id == hgar_file.id).first()
                    if not raw:
                        logger.warning("    WARNING: No Raw data for %s", hgar_file.short_name)
                        continue
                    content = raw.content
                
                # 检查是否需要重新压缩（根据 encoded_identifier）
                is_compressed = ((hgar_file.encoded_identifier >> 31) == 1) if hgar_file.encoded_identifier else False
                
                if is_compressed:
                    # 重新压缩数据
                    import zlib
                    original_size = len(content)
                    compressed = zlib.compress(content)
                    # 跳过 2 字节头部和 4 字节校验和
                    compressed_content = compressed[2:-4]
                    
                    # 构建压缩格式：size(4 bytes) + compressed_data
                    import struct
                    final_content = struct.pack('<I', original_size) + compressed_content
                    
                    logger.debug("  [COMPRESS] %s: %d → %d bytes", hgar_file.short_name, original_size, len(compressed_content))
                    content = final_content
                
                # 构建 HGArchiveFile 对象
                size = len(content)
                hg_archive_files.append(
                    tools.HGArchiveFile(
                        long_name=hgar_file.long_name,
                        short_name=hgar_file.short_name,
                        size=size,
                        encoded_identifier=hgar_file.encoded_identifier,
                        unknown_first=hgar_file.unknown_first,
                        unknown_last=hgar_file.unknown_last,
                        content=content,
                    )
                )
            # print(f"Formed {(hg_archive_files)}")
            return hg_archive_files
