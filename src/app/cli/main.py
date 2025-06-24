import os
import argparse

from app.parser import tools

from app.database.dao.hgar import HGARDao
from app.database.dao.sentence import SentenceDao
from app.database.dao.translation import TranslationDao

from app.database.db import Base, engine
from app.utils.evs import get_avatar_and_exp

HGAR_PREFIX = ["a", "b2a", "b2s", "bb", "bs", "cev", "e", "f", "levent", "n", "tev"]


class App:
    def __init__(self):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        pass

    def import_har(dir_path: str):
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".har"):
                    App.decompile_hgar(os.path.join(root, file))
            pass

    def compile_hgar(name: str, output_dir: str):
        hgar: tools.HGArchive = HGARDao.get_hgar_by_name(name)
        hgar.save(os.path.join(output_dir, name))
        pass

    def output_hgar(output_dir: str):
        for prefix in HGAR_PREFIX:
            print(f"Exporting {prefix}")
            names, hgars = HGARDao.get_hgar_by_prefix(prefix)
            for name, hgar in zip(names, hgars):
                hgar.save(os.path.join(output_dir, name))
        pass

    def decompile_hgar(path: str):
        hgar = tools.HGArchive(None, [])
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
                list.append(
                    {
                        "key": key,
                        "original": original,
                        "context": f"AVA: {avatar}\nEXP: {exp}",
                    }
                )
            # Write to file
            with open(f"{path}/{prefix}.json", "w") as f:
                import json

                f.write(json.dumps(list, indent=4, ensure_ascii=False))

    def import_translation(filepath: str):
        # Drop all translations
        TranslationDao.delete_all()
        with open(filepath, "r") as f:
            import json

            data = json.load(f)
            TranslationDao.save_translations(data)
        pass

    def output_translation(output_dir):
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
                list.append(
                    {
                        "key": key,
                        "original": original,
                        "translation": TranslationDao.get_translation_by_key(key),
                        "context": f"AVA: {avatar}\nEXP: {exp}",
                    }
                )

            # Write to file
            with open(f"{output_dir}/{prefix}.json", "w") as f:
                import json

                f.write(json.dumps(list, indent=4, ensure_ascii=False))
        pass

    def output_images():
        pass

    def update_images():
        pass

    def compile():
        pass


if __name__ == "__main__":
    # HGAR ARG
    parser = argparse.ArgumentParser(description="Import/Export NGE2 Game Assets")

    # Import All HGAR files
    parser.add_argument("--import_har", type=str, help="The path to the HAR file")

    # TODO: Import TEXT/BIN files

    # Export EVS Original
    parser.add_argument(
        "--export_evs", type=str, help="Path for exporting EVS Originals"
    )

    # Import Translations
    parser.add_argument(
        "--import_translation",
        type=str,
        help="Path of the translation file from Paratranz",
    )

    # Export Translations
    parser.add_argument(
        "--export_translation", type=str, help="Path for exporting translations"
    )

    # Output HGAR
    parser.add_argument("--output_hgar", type=str, help="Path for exporting HGAR files")

    # TODO: Import/Export Images

    args = parser.parse_args()
    if args.import_har:
        App()
        App.import_har(os.path.dirname(args.import_har))
    elif args.export_evs:
        App.output_evs(args.export_evs)
    elif args.import_translation:
        App.import_translation(args.import_translation)
    elif args.export_translation:
        App.output_translation(args.export_translation)
    elif args.output_hgar:
        App.output_hgar(args.output_hgar)
