"""
Obtain a sentence with or without translation from the database.
"""

from ..db import engine, Base, get_db

# Entities
from ..entity.entry import Entry
from ..entity.sentence import Sentence
from ..entity.translation import Translation

def save(sentence: Sentence):
    with next(get_db()) as db:
        db.add(sentence)
        db.commit()
        db.refresh(sentence)
        return sentence
    
def get_sentence_by_key(key: int):
    with next(get_db()) as db:
        return db.query(Sentence).filter(Sentence.key == key).first()

def get_source_and_translation_by_key(key: int):
    with next(get_db()) as db:
        return db.query(Sentence, Translation).filter(Sentence.key == key).join(Translation).first()