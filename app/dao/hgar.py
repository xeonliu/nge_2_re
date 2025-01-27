"""
Obtain a sentence with or without translation from the database.
"""

from ..db import engine, Base, get_db
from tools.hgar import HGArchive, HGArchiveFile

# Entities
from ..entity.entry import Entry
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile
from ..entity.evs import EVS

from .hgar_file import HGARFileDao

class HGARDao:
    def save(filename: str, hg_archive: HGArchive):
        hgar = Hgar(name = filename, version=hg_archive.version)
        with next(get_db()) as db:
            db.add(hgar)
            db.commit()
            db.refresh(hgar)
        HGARFileDao.save(hgar.id, hg_archive.files)
        return hgar
    
def get_evs_list_by_key(key: int):
    with next(get_db()) as db:
        hgar = db.query(Hgar).filter(Hgar.key == key).first()
        return db.query(Evs).filter(Evs.hgar_id == hgar.id).all()
        