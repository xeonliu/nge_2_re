from sqlalchemy import Column, ForeignKey, Integer, String, ARRAY, JSON
from ..db import Base

class EVSEntry(Base):
    __tablename__ = 'evs_entries'

    id = Column(Integer, primary_key=True, index=True)
    type = Column(Integer)
    # Calculated at runtime
    # size = Column(Integer)
    param = Column(JSON)
    sentence_key = Column(String, ForeignKey('sentences.key'), nullable=True)
    
    hgar_file_id = Column(Integer, ForeignKey('hgar_files.id'), index=True)
    
    def __repr__(self):
        pass