from sqlalchemy import Column, ForeignKey, Integer, String
from ..db import Base

class EVS(Base):
    __tablename__ = 'evs'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    hgar_id = Column(Integer, ForeignKey('hgar.id'), index=True)

    def __repr__(self):
        return f"<EVS(name='{self.name}', hgar_id='{self.hgar_id}')>"