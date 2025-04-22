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
    
    def get_hgar_by_name(name: str) -> HGArchive:
        with next(get_db()) as db:
            hgar = db.query(Hgar).filter(Hgar.name == name).first()
            # Form a list of HGArchiveFile
            hgar_files = HGARFileDao.form(hgar.id)
            # Form HGArcive
            return HGArchive(hgar.version, hgar_files)
    
    def get_hgar_by_prefix(prefix: str):
        with next(get_db()) as db:
            hgars = db.query(Hgar).filter(Hgar.name.like(f"{prefix}%")).all()
            hgar_names = []
            hgar_archives = []
            for hgar in hgars:
                # try:
                hgar_files = HGARFileDao.form(hgar.id)
                # except:
                #     print(f"Error in {hgar.name}")
                #     continue
                hgar_archives.append(HGArchive(hgar.version, hgar_files))
                hgar_names.append(hgar.name)
            return hgar_names, hgar_archives