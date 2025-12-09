from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database.db import Base


class HgarFile(Base):
    """
    HGAR压缩包中的文件Entry
    一个文件可能对应一个HGPT图像，也可能是其他类型的文件（EVS等）
    """
    __tablename__ = "hgar_files"

    id = Column(Integer, primary_key=True, index=True)
    short_name = Column(String, index=True)
    long_name = Column(String, index=True, nullable=True)
    # Size: Calculate at runtime from content
    file_size = Column(Integer, nullable=True)  # 原始文件大小
    compressed_size = Column(Integer, nullable=True)  # 压缩后大小
    encoded_identifier = Column(Integer)
    unknown_first = Column(Integer, nullable=True)
    unknown_last = Column(Integer, nullable=True)
    
    # Foreign Keys
    hgar_id = Column(Integer, ForeignKey("hgars.id"), index=True, nullable=False)
    # 如果是 HGPT 文件，关联到去重后的 HGPT 数据
    hgpt_key = Column(String, ForeignKey("hgpts.key"), index=True, nullable=True)
    
    # Relationships
    hgar = relationship("Hgar", back_populates="files")
    hgpt = relationship("Hgpt", back_populates="hgar_files")

    def __repr__(self):
        return f"<HgarFile(short_name='{self.short_name}', hgar_id={self.hgar_id})>"
