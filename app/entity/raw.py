from sqlalchemy import Column, ForeignKey, Integer, LargeBinary
from ..db import Base


class Raw(Base):
    __tablename__ = "raws"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(LargeBinary, nullable=False)

    hgar_file_id = Column(Integer, ForeignKey("hgar_files.id"), index=True)

    def __repr__(self):
        return f"<Raw(hgar_file_id='{self.hgar_file_id}')>"
