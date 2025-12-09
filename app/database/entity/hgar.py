from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from ..db import Base


class Hgar(Base):
    """
    代表HGAR压缩包
    """
    __tablename__ = "hgars"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, unique=True)
    version = Column(Integer)
    
    # Relationships
    files = relationship("HgarFile", back_populates="hgar", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Hgar(name='{self.name}', version={self.version})>"
