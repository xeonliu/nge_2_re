"""
Obtain a sentence with or without translation from the database.
"""

from sqlalchemy import distinct, func
from ..db import engine, Base, get_db

# Entities
from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.translation import Translation
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile

class SentenceDao:
    def save(sentence: Sentence):
        with next(get_db()) as db:
            db.add(sentence)
            db.commit()
            db.refresh(sentence)
            return sentence
        
    # def get_sentence_by_key(key: int):
    #     with next(get_db()) as db:
    #         return db.query(Sentence).filter(Sentence.key == key).first()

    # def get_source_and_translation_by_key(key: int):
    #     with next(get_db()) as db:
    #         return db.query(Sentence, Translation).filter(Sentence.key == key).join(Translation).first()
        
    def export_sentence_json(prefix: str):
        # with next(get_db()) as db:
        #     results = db.query(Sentence)\
        #         .join(EVSEntry, Sentence.key == EVSEntry.sentence_key)\
        #             .join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)\
        #                 .join(Hgar, HgarFile.hgar_id == Hgar.id)\
        #                     .filter(Hgar.name.like(f"{prefix}%"))\
        #                         .filter(EVSEntry.type==1).distinct(Sentence.id).all()
        #     for result in results:
        #         print(result,"\n")
        # return results
        with next(get_db()) as db:
            subquery = db.query(
                EVSEntry.sentence_key,
                func.min(EVSEntry.id).label('min_id')
            ).join(HgarFile, EVSEntry.hgar_file_id == HgarFile.id)\
             .join(Hgar, HgarFile.hgar_id == Hgar.id)\
             .filter(Hgar.name.like(f"{prefix}%"))\
             .filter(EVSEntry.type == 1)\
             .group_by(EVSEntry.sentence_key)\
             .subquery()

            results = db.query(Sentence, EVSEntry)\
                .join(subquery, Sentence.key == subquery.c.sentence_key)\
                .join(EVSEntry, EVSEntry.id == subquery.c.min_id)\
                .order_by(Sentence.id)\
                .all()
            return results