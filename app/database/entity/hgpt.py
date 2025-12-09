from typing import Any

from sqlalchemy import Column, Integer, String, LargeBinary, Boolean, JSON, Index
from sqlalchemy.orm import relationship
from ..db import Base


class Hgpt(Base):
    """
    HGPT 图像数据（去重存储）
    参考 Sentence 的设计模式：使用 hash key 去重，同一个图像只存储一次
    多个 HgarFile 可以引用同一个 Hgpt
    """
    __tablename__ = "hgpts"

    id = Column(Integer, primary_key=True, index=True)
    
    # 用于去重的哈希值（MD5，基于原始 HGPT 数据）
    key = Column(String, unique=True, index=True, nullable=False)
    
    # 存储原始解压后的 HGPT 二进制数据（用于重建文件）
    content = Column(LargeBinary, nullable=False)
    
    # 存储导出的 PNG 图像（原版，用于预览）
    png_image = Column(LargeBinary, nullable=True)
    
    # 存储翻译后的 PNG 图像（优先使用）
    png_translated = Column(LargeBinary, nullable=True)
    
    # Metadata from HgptHeader
    has_extended_header = Column(Boolean, nullable=False, default=False)
    unknown_two = Column(Integer, default=0)
    unknown_three = Column(Integer, default=0x0013)
    
    # Metadata from DisplayInfo
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    
    # Format info (从 PP 段推断)
    pp_format = Column(Integer, nullable=True)  # 0x13, 0x14, 0x8800 等
    
    # Palette info
    palette_size = Column(Integer, nullable=True)  # None for RGBA images
    
    # Division Info (from DivisionInfo)
    division_name = Column(String, nullable=True)
    divisions: Any = Column(JSON, nullable=True)  # List[Tuple[int,int,int,int]]
    
    # Relationships
    hgar_files = relationship("HgarFile", back_populates="hgpt")

    def __repr__(self):
        return f"<Hgpt(key='{self.key[:8]}...', size={self.width}x{self.height}, format=0x{self.pp_format:X if self.pp_format else 0})>"


# 为常用查询创建复合索引
Index('idx_hgpt_dimensions', Hgpt.width, Hgpt.height)
