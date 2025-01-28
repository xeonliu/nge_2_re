"""
Obtain a sentence with or without translation from the database.
"""

from ..db import engine, Base, get_db
from tools.hgar import HGArchive, HGArchiveFile
from tools.evs import EvsWrapper

# Entities
from ..entity.evs_entry import EVSEntry
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile
from ..entity.evs_entry import EVSEntry
from ..entity.raw import Raw

from .evs import EVSDao

class HGARFileDao:
    def save(hgar_id: int, hgar_files: list[HGArchiveFile]):
        for file in hgar_files:
            with next(get_db()) as db:
                # FIXME: Remove decode
                short_name:str = file.short_name.decode('ascii').rstrip(' \t\r\n\0')
                hgar_file = HgarFile(hgar_id=hgar_id, short_name=short_name, long_name=file.long_name, encoded_identifier=file.encoded_identifier, unknown_fist=file.unknown_first, unknown_last=file.unknown_last)
                db.add(hgar_file)
            
                content = file.content
                # TODO: Compression Check

                # TODO: Type Check
                if short_name.endswith(".evs"):
                    evs_wrapper = EvsWrapper()
                    evs_wrapper.open_bytes(content)
                    print("Save evs")
                    # Persisit Entries
                    EVSDao.save(hgar_file.id, evs_wrapper)
                elif short_name.endswith(".hpt"):
                    pass
                else:
                    raw = Raw(hgar_file_id=hgar_file.id, content=content)
                    db.add(raw)
                db.commit()
        return hgar_files
            