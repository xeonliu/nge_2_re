from sqlalchemy import Column, ForeignKey, Integer, String
from ..db import Base

class Translation(Base):
    __tablename__ = 'translations'

    id = Column(Integer, primary_key=True, index=True)
    key = Column(Integer, index=True)
    content = Column(String)
    
    def __repr__(self):
        return f"<Translation(id='{self.id}', key='{self.key}', content='{self.content}')>"