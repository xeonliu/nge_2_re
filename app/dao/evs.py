"""
Persist EVSWrapper
"""

import hashlib

from ..db import get_db
from tools.evs import EvsWrapper

from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.translation import Translation


class EVSDao:
    def save(hgar_file_id: int, evs_file: EvsWrapper):
        # Save All the Entries
        with next(get_db()) as db:
            for type, params, content in evs_file.entries:
                print("evs", type, params, content)
                # Entry Type
                # Entry Parameters

                # Entry Content
                if content == None:
                    continue
                elif len(content) == 0:
                    continue

                # Hash the content.
                hash_object = hashlib.md5(content.encode())
                hashed_str = hash_object.hexdigest()

                # Store the Sentence
                if (
                    db.query(Sentence).filter(Sentence.key == hashed_str).scalar()
                    == None
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

    def form_evs_wrapper(hgar_file_id: int) -> EvsWrapper:
        with next(get_db()) as db:
            evs_entries = (
                db.query(EVSEntry).filter(EVSEntry.hgar_file_id == hgar_file_id).all()
            )
            evs = EvsWrapper()
            for entry in evs_entries:
                translation = (
                    db.query(Translation)
                    .filter(Translation.key == entry.sentence_key)
                    .first()
                )
                original = db.query(Sentence).filter(Sentence.key == entry.sentence_key).first()
                content = original.content
                if translation:
                    content = translation.content
                evs.add_entry(entry.type, entry.param, content)
            return evs
