from sqlalchemy import Column, Integer, String, LargeBinary, Text
from ..db import Base


class BindEntry(Base):
    """
    BIND 归档文件条目（imtext.bin, btimtext.bin 等）
    每个 BIND 文件包含多个二进制条目
    """
    __tablename__ = "bind_entries"

    id = Column(Integer, primary_key=True, index=True)
    
    # BIND 文件名（如 imtext.bin）
    filename = Column(String, index=True, nullable=False)
    
    # 条目在 BIND 文件中的索引（从 0 开始）
    entry_index = Column(Integer, nullable=False)
    
    # 原始二进制内容
    content = Column(LargeBinary, nullable=False)
    
    # 如果内容是文本，可以提取并存储原始文本
    # 用于翻译和查询（可选）
    text_content = Column(Text, nullable=True)
    
    # BIND 元数据
    size_byte_size = Column(Integer, default=4)
    block_size = Column(Integer, default=2048)

    def __repr__(self):
        size = len(self.content) if self.content else 0
        return (
            f"<BindEntry(filename='{self.filename}', index={self.entry_index}, "
            f"size={size})>"
        )
