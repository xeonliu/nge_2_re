from sqlalchemy import Column, Integer, String
from ..db import Base


class Sentence(Base):
    __tablename__ = "sentences"

    id = Column(Integer, primary_key=True, index=True)
    # Sentence Text Hash
    key = Column(String, index=True)
    content = Column(String)

    def __repr__(self):
        return f"<Sentence(content='{self.content}'), key='{self.key}'>"
