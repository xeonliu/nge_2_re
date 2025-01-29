import os
import argparse

from tools.hgar import HGArchive
from app.dao.hgar import HGARDao
from app.dao.sentence import SentenceDao
from app.db import Base, engine
from app.utils.evs import get_avatar_and_exp

HGAR_PREFIX = ["a", "b2a", "b2s", "bb", "bs", "cev", "e", "f","levent", "n", "tev"]
class App:
    def __init__(self):
        # Base.metadata.create_all(bind=engine)
        pass

    def clear():
        Base.metadata.drop_all(bind=engine)

    def import_har(dir_path: str):
        for root,_,files in os.walk(dir_path):
            for file in files:
                if file.endswith(".har"):
                    App.decompile_hgar(os.path.join(root, file))
            pass
    
    def compile_hgar(name: str, output_dir: str):
        pass

    def decompile_hgar(path: str):
        hgar = HGArchive()
        hgar.open(path)
        
        filename = os.path.basename(path)
        print(f"Extracted filename: {filename}")
        
        # Store HGAR & HGAR Files into DB
        HGARDao.save(filename, hgar)
        
        hgar.info()
    
    def output_evs(path: str):
        for prefix in HGAR_PREFIX:
            print(f"Exporting {prefix}")
            results = SentenceDao.export_sentence_entry(prefix)
            list = []
            for sentence, evs_entry in results:
                avatar, exp = get_avatar_and_exp(evs_entry.param[0], evs_entry.param[1])
                key = sentence.key
                original = sentence.content
                # print(f"\n{key}:\n {original} AVA:{avatar}\n EXP:{exp}")
                # {
                #     "key": "KEY 键值",
                #     "original": "source text 原文",
                #     "translation": "translation text 译文",
                #     "context": "Context 上下文 (for info)"
                # }
                # Find translation
                list.append({
                    "key": key,
                    "original": original,
                    "context": f"AVA: {avatar}\nEXP: {exp}"
                })
            # Write to file
            with open(f"{path}/{prefix}.json", "w") as f:
                import json
                f.write(json.dumps(list, indent=4,ensure_ascii=False))
    
    def import_translation():
        pass

    def output_translation(output_dir):
        pass
        
    def output_images():
        pass

    def update_images():
        pass

    def compile():
        pass


if __name__ == "__main__":
    # HGAR ARG
    parser = argparse.ArgumentParser(description='Import/Export NGE2 Game Assets')
    
    # Import All HGAR files
    parser.add_argument('--import_har', type=str, help='The path to the HAR file')

    # TODO: Import TEXT/BIN files
    
    # Export EVS Original
    parser.add_argument('--export_evs', type=str, help='Path for exporting EVS Originals')

    # Import Translations
    parser.add_argument('--import_translation', type=str, help='Path of the translation file from Paratranz')

    # Export Translations
    parser.add_argument('--export_translation', type=str, help='Path for exporting translations')

    # TODO: Import/Export Images

    args = parser.parse_args()
    if args.import_har:
        App.import_har(os.path.dirname(args.import_har))
    elif args.export_evs:
        App.output_evs(args.export_evs)
