from sqlalchemy import Column, Integer, String
from ..db import Base

class Hgar(Base):
    __tablename__ = 'hgars'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    version = Column(Integer)
    
    def __repr__(self):
        return f"<HGAR(name='{self.name}')>"