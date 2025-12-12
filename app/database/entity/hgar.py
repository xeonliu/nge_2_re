from sqlalchemy import Column, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship
from ..db import Base


class Hgar(Base):
    """
    代表HGAR压缩包
    """
    __tablename__ = "hgars"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    version = Column(Integer)
    relative_path = Column(String, default="", index=True)  # 相对于导入根目录的路径，如 "events"、"free" 等
    
    # 组合唯一约束：同一路径下不能有同名文件
    __table_args__ = (
        UniqueConstraint('name', 'relative_path', name='uix_hgar_name_path'),
    )
    
    # Relationships
    files = relationship("HgarFile", back_populates="hgar", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Hgar(name='{self.name}', version={self.version})>"
