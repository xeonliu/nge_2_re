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
                short_name: str = file.short_name.decode("ascii").rstrip(" \t\r\n\0")
                hgar_file = HgarFile(
                    hgar_id=hgar_id,
                    short_name=short_name,
                    long_name=file.long_name,
                    encoded_identifier=file.encoded_identifier,
                    unknown_fist=file.unknown_first,
                    unknown_last=file.unknown_last,
                )
                db.add(hgar_file)
                db.commit()

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

    def form(hgar_id: int) -> list[HGArchiveFile]:
        with next(get_db()) as db:
            print(f"Form HGAR Files for {hgar_id}")
            hgar_files = (
                db.query(HgarFile)
                .filter(HgarFile.hgar_id == hgar_id)
                .order_by(HgarFile.id.asc())
                .all()
            )
            hg_archive_files = []
            for hgar_file in hgar_files:
                print(f"Short Name: {hgar_file.short_name}")
                if hgar_file.short_name.endswith(".evs"):
                    evs_wrapper: EvsWrapper = EVSDao.form_evs_wrapper(hgar_file.id)
                    content = evs_wrapper.save_bytes()
                    size = len(content)
                    # print(f"Size: {size}")
                    hg_archive_files.append(
                        HGArchiveFile(
                            long_name=hgar_file.long_name,
                            short_name=hgar_file.short_name,
                            size=size,
                            encoded_identifier=hgar_file.encoded_identifier,
                            unknown_first=hgar_file.unknown_fist,
                            unknown_last=hgar_file.unknown_last,
                            content=content,
                        )
                    )
                # TODO
                # elif hgar_file.short_name.endswith(".hpt"):
                #     pass
                else:
                    # TODO: Raw原样放回即可，如果不是RAW，要去除压缩Flag
                    # TODO: 计算Size
                    raw = db.query(Raw).filter(Raw.hgar_file_id == hgar_file.id).first()
                    size = len(raw.content)
                    # print(f"Size: {size}")
                    hg_archive_files.append(
                        HGArchiveFile(
                            long_name=hgar_file.long_name,
                            short_name=hgar_file.short_name,
                            size=size,
                            encoded_identifier=hgar_file.encoded_identifier,
                            unknown_first=hgar_file.unknown_fist,
                            unknown_last=hgar_file.unknown_last,
                            content=raw.content,
                        )
                    )
            # print(f"Formed {(hg_archive_files)}")
            return hg_archive_files
