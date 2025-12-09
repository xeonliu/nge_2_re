from sqlalchemy import Column, Integer, LargeBinary, ForeignKey
from sqlalchemy.orm import relationship
from ..db import Base


class Raw(Base):
    """
    Raw 代表 HGAR File 中无法解析的文件（非 HGPT、非 EVS 格式）
    """
    __tablename__ = "raws"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(LargeBinary, nullable=False)

    hgar_file_id = Column(Integer, ForeignKey("hgar_files.id"), index=True, unique=True)
    
    # Relationship
    hgar_file = relationship("HgarFile")

    def __repr__(self):
        return f"<Raw(hgar_file_id={self.hgar_file_id}, size={len(self.content) if self.content else 0})>"
