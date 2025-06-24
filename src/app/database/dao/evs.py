"""
Persist EVSWrapper
"""

import hashlib

from ..db import get_db
from app.parser import tools

from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.translation import Translation


class EVSDao:
    def save(hgar_file_id: int, evs_file: tools.EvsWrapper):
        # Save All the Entries
        with next(get_db()) as db:
            for type, params, content in evs_file.entries:
                print("evs", type, params, content)
                # Entry Type
                # Entry Parameters

                # Entry Content
                if content is None or len(content) == 0:
                    evs = EVSEntry(
                        type=type,
                        param=params,
                        sentence_key=None,
                        hgar_file_id=hgar_file_id,
                    )
                    db.add(evs)
                    continue

                # Hash the content.
                hash_object = hashlib.md5(content.encode())
                hashed_str = hash_object.hexdigest()

                # Store the Sentence
                if (
                    db.query(Sentence).filter(Sentence.key == hashed_str).scalar()
                    is None
                ):
                    sentence = Sentence(key=hashed_str, content=content)
                    print("Evs add")
                    db.add(sentence)
                    db.commit()

                evs = EVSEntry(
                    type=type,
                    param=params,
                    sentence_key=hashed_str,
                    hgar_file_id=hgar_file_id,
                )
                db.add(evs)
            db.commit()

    def form_evs_wrapper(hgar_file_id: int) -> tools.EvsWrapper:
        with next(get_db()) as db:
            evs_entries = (
                db.query(EVSEntry)
                .filter(EVSEntry.hgar_file_id == hgar_file_id)
                .order_by(EVSEntry.id.asc())
                .all()
            )
            print(evs_entries)
            evs = tools.EvsWrapper()
            for entry in evs_entries:
                if entry.sentence_key is None:
                    evs.add_entry(entry.type, entry.param, b"")
                    continue
                translation = (
                    db.query(Translation)
                    .filter(Translation.key == entry.sentence_key)
                    .first()
                )
                original = (
                    db.query(Sentence)
                    .filter(Sentence.key == entry.sentence_key)
                    .first()
                )
                content = original.content
                if translation:
                    content = translation.content
                print(content)
                evs.add_entry(entry.type, entry.param, content)
            return evs
