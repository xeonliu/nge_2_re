"""
Obtain a sentence with or without translation from the database.
"""

from ..db import engine, Base, get_db
from tools.hgar import HGArchive, HGArchiveFile

# Entities
from ..entity.evs_entry import EVSEntry
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile

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
        pass