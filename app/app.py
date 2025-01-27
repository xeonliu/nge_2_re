import os
import argparse

from tools.hgar import HGArchive
from app.dao.hgar import HGARDao
from app.db import Base, engine
class App:
    def __init__(self):
        from .entity.sentence import Sentence
        from .entity.entry import Entry
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        pass
    
    def extract():
        pass

    def output_translation():
        pass

    def update_translation():
        pass

    def output_images():
        pass

    def update_images():
        pass

    def compile():
        pass

    def compile_hgar(name: str):
        pass
    def decompile_hgar(path: str):
        hgar = HGArchive()
        hgar.open(path)
        
        filename = os.path.basename(path)
        print(f"Extracted filename: {filename}")
        
        # Store HGAR into DB
        # Store HGAR Files into DB
        HGARDao.save(filename, hgar)
        hgar.info()
        pass

if __name__ == "__main__":
    # HGAR ARG
    parser = argparse.ArgumentParser(description='Process a HAR file.')
    parser.add_argument('har_file', type=str, help='The path to the HAR file')
    args = parser.parse_args()

    app = App()
    print(args.har_file)
    App.decompile_hgar(args.har_file)
    # extract()
    # output_translation()
    # update_translation()