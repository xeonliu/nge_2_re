from sqlalchemy import distinct, func
from ..db import engine, Base, get_db

# Entities
from ..entity.evs_entry import EVSEntry
from ..entity.sentence import Sentence
from ..entity.translation import Translation
from ..entity.hgar import Hgar
from ..entity.hgar_file import HgarFile
from ..entity.translation import Translation

class TranslationDao:
    def save(translation: Translation):
        with next(get_db()) as db:
            db.add(translation)
            db.commit()
            db.refresh(translation)
            return translation
        
    def save_translation_entry(key:str, translation:str):
        translation = Translation(key=key, content=translation)
        return TranslationDao.save(translation)
    
    def get_translation_by_key(key: str):
        with next(get_db()) as db:
            trans = db.query(Translation).filter(Translation.key == key).first()
            return trans.content