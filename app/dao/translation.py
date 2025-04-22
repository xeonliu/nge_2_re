from ..db import get_db

# Entities
from ..entity.translation import Translation


class TranslationDao:
    def delete_all():
        with next(get_db()) as db:
            db.query(Translation).delete()
            db.commit()

    def save(translation: Translation):
        with next(get_db()) as db:
            db.add(translation)
            db.commit()
            db.refresh(translation)
            return translation

    def save_translations(data):
        """
        data = [
        {
        key:
        content:
        }
        ]
        """
        with next(get_db()) as db:
            for d in data:
                translation = Translation(key=d["key"], content=d["translation"])
                db.add(translation)
            db.commit()

    def save_translation_entry(key: str, translation: str):
        print("Save Translation", key, translation)
        translation = Translation(key=key, content=translation)
        return TranslationDao.save(translation)

    def get_translation_by_key(key: str):
        with next(get_db()) as db:
            trans = db.query(Translation).filter(Translation.key == key).first()
            return trans.content
