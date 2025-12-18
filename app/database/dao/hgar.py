"""
Obtain a sentence with or without translation from the database.
"""

from ..db import get_db

from app.parser import tools

# Entities
from ..entity.hgar import Hgar

from .hgar_file import HGARFileDao

class HGARDao:
    """
    记录 HGAR 归档文件的元数据，其名称、位置、版本等
    """
    @staticmethod
    def save(filename: str, hg_archive: tools.HGArchive, relative_path: str = ""):
        hgar = Hgar(name=filename, version=hg_archive.version, relative_path=relative_path)
        with next(get_db()) as db:
            db.add(hgar)
            db.commit()
            db.refresh(hgar)
        HGARFileDao.save(hgar.id, hg_archive.files)
        return hgar

    @staticmethod
    def get_hgar_by_name(name: str) -> tools.HGArchive:
        with next(get_db()) as db:
            hgar = db.query(Hgar).filter(Hgar.name == name).first()
            # Form a list of HGArchiveFile
            hgar_files = HGARFileDao.form(hgar.id)
            # Form HGArcive
            return tools.HGArchive(hgar.version, hgar_files)

    @staticmethod
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
                hgar_archives.append(tools.HGArchive(hgar.version, hgar_files))
                hgar_names.append(hgar.name)
            return hgar_names, hgar_archives

    @staticmethod
    def get_all_hgar_names():
        """获取所有 HGAR 文件的名称"""
        with next(get_db()) as db:
            hgars = db.query(Hgar).all()
            return [hgar.name for hgar in hgars]
    
    @staticmethod
    def get_all_hgars():
        """获取所有 HGAR 文件的完整信息（name, relative_path, archive）"""
        with next(get_db()) as db:
            hgars = db.query(Hgar).all()
            results = []
            for hgar in hgars:
                hgar_files = HGARFileDao.form(hgar.id)
                archive = tools.HGArchive(hgar.version, hgar_files)
                results.append((hgar.name, hgar.relative_path, archive))
            return results
