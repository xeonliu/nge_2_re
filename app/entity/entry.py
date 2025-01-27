from sqlalchemy import Column, ForeignKey, Integer, String, ARRAY, JSON
from ..db import Base

class Entry(Base):
    __tablename__ = 'entries'

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Integer)
    size = Column(Integer)
    param = Column(JSON)
    sentence_key = Column(Integer, ForeignKey('sentences.key'), nullable=True)
    
    evs_id = Column(Integer, ForeignKey('evs.id'), index=True)

    def __repr__(self):
        return f"<Entry(type='{self.type}', size='{self.size}', param='{self.param}', sentence_key='{self.sentence_key}', evs_id='{self.evs_id}')>"