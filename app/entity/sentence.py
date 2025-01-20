from sqlalchemy import Column, ForeignKey, Integer, String
from ..db import Base

class Sentence(Base):
    __tablename__ = 'sentences'

    id = Column(Integer, primary_key=True, index=True)
    # Sentence Text Hash
    key = Column(Integer, index=True)
    content = Column(String)

    def __repr__(self):
        return f"<EVS(name='{self.name}', hgar_id='{self.hgar_id}')>"