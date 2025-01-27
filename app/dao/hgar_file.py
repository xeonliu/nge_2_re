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
from ..entity.raw import Raw

class HGARFileDao:
    def save(hgar_id: int, hgar_files: list[HGArchiveFile]):
        for file in hgar_files:
            with next(get_db()) as db:
                # FIXME: Remove decode
                short_name = file.short_name.decode('ascii').rstrip(' \t\r\n\0')
                hgar_file = HgarFile(hgar_id=hgar_id, short_name=short_name, long_name=file.long_name, encoded_identifier=file.encoded_identifier, unknown_fist=file.unknown_first, unknown_last=file.unknown_last)
                db.add(hgar_file)
                db.commit()

                content = file.content
                # TODO: Compression Check
                # TODO: Type Check
                raw = Raw(hgar_file_id=hgar_file.id, content=content)
                db.add(raw)
                db.commit()
        return hgar_files
            