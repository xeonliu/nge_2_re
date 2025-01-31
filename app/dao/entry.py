# from ..db import engine, Base, get_db

# # Entities
# from ..entity.evs_entry import Entry
# from ..entity.hgar import Hgar
# from ..entity.evs import Evs

# def save(entry: Entry):
#     with next(get_db()) as db:
#         db.add(entry)
#         db.commit()
#         db.refresh(entry)
#         return entry