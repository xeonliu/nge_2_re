from sqlalchemy import Column, Integer, String,ForeignKey
from app.db import Base

class HgarFile(Base):
    __tablename__ = 'hgar_files'

    id = Column(Integer, primary_key=True, index=True)
    short_name = Column(String, index=True)
    long_name = Column(String, index=True, nullable=True)
    # Size: Calculate at runtime
    encoded_identifier = Column(Integer)
    unknown_fist = Column(Integer, nullable=True)
    unknown_last = Column(Integer, nullable=True)
    # Content
    
    hgar_id = Column(Integer, ForeignKey('hgars.id'), index=True)
    
    def __repr__(self):
        return f"<HGAR(name='{self.name}')>"