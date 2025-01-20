from sqlalchemy import Column, ForeignKey, Integer, String, LargeBinary
from ..db import Base

class Raw(Base):
    __tablename__ = 'raws'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    raw = Column(LargeBinary, nullable=False)

    hgar_id = Column(Integer, ForeignKey('hgar.id'), index=True)

    def __repr__(self):
        return f"<Raw(name='{self.name}', hgar_id='{self.hgar_id}')>"