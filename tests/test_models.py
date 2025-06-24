import unittest

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from app.database.entity.sentence import Sentence
from app.database.db import Base, engine, get_db


class TestSentenceModel(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = next(get_db())

    def tearDown(self):
        # Drop all tables
        Base.metadata.drop_all(bind=engine)
        self.db.close()

    def test_save_sentence(self):
        sentence = Sentence(key=1, content="Hello, world!")
        self.db.add(sentence)
        self.db.commit()
        self.db.refresh(sentence)
        self.assertEqual(sentence.key, "1")
        self.assertEqual(sentence.content, "Hello, world!")


if __name__ == "__main__":
    unittest.main()
