from sqlalchemy import Column, Integer, String, LargeBinary, UniqueConstraint
from ..db import Base


class TextEntry(Base):
    """
    TEXT 文件条目（f2tuto.bin, f2info.bin 等）
    复用 Translation 表的翻译内容
    """
    __tablename__ = "text_entries"

    id = Column(Integer, primary_key=True, index=True)
    
    # TEXT 文件名（如 f2info.bin）
    filename = Column(String, index=True, nullable=False)
    
    # 原始字符串内容
    original = Column(String, nullable=False)
    
    # 条目的 unknown 值（在二进制文件中的固定值）
    entry_unknown = Column(Integer, default=0)
    
    # 字符串的索引号
    string_index = Column(Integer, nullable=False)
    
    # unknown_first 和 unknown_second 字段（字符串本身的 unknown 值）
    unknown_first = Column(Integer, default=0)
    unknown_second = Column(Integer, default=0)
    
    # 保留元数据
    header_padding = Column(Integer, default=0)
    entry_padding = Column(Integer, default=0)
    
    # 唯一约束：同一文件中不能有相同索引的条目
    __table_args__ = (
        UniqueConstraint('filename', 'string_index', name='uix_text_filename_index'),
    )

    def __repr__(self):
        return (
            f"<TextEntry(filename='{self.filename}', index={self.string_index}, "
            f"original='{self.original[:50]}...')>"
        )
