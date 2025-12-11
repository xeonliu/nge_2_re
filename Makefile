# Temporary working directory
TEMP_DIR := temp
# Directory for downloaded translation files (from ParaTranz)
DOWNLOAD_DIR := $(TEMP_DIR)/downloads
# Path to the PSP_GAME directory
PSP_GAME_DIR := $(TEMP_DIR)/ULJS00064/PSP_GAME_DIR

# TODO: Work Folder

# USRDIR Directories
EVENT_DIR := ${PSP_GAME_DIR}/USRDIR/event

### Import Game Files
# TODO: Add other HGAR Files
import_hgar: import_event import_game

import_event:
	@echo "Importing event hgar..."
	uv run -m app.cli.main --import_har '$(EVENT_DIR)' 

import_text:
	@echo "Importing text entries..."
	uv run -m app.cli.main --import_text '${PSP_GAME_DIR}/USRDIR/free/f2info.bin' '${PSP_GAME_DIR}/USRDIR/free/f2tuto.bin'

### Translation Tasks
download_translations:
	@echo "Downloading translations..."
	@mkdir -p $(DOWNLOAD_DIR)
	uv run scripts/paratranz/download.py  --dest_folder $(DOWNLOAD_DIR)

check_translations: $(DOWNLOAD_DIR)/evs_trans.json
	@echo "Checking EVS translations..."
	uv run -m scripts.check '$(DOWNLOAD_DIR)/evs_trans.json' build/evs_report.json evs
	@echo "Checking EBOOT translations..."
	uv run -m scripts.check '$(DOWNLOAD_DIR)/eboot_trans.json' build/eboot_report.json eboot

import_translations:
	@echo "Importing translations..."
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/evs_trans.json'

### Export Game Files
export_text:
	@echo "Exporting text entries..."
	uv run -m app.cli.main --export_text build

export_hgar:
	@echo "Generating hgar..."
	uv run -m app.cli.main --output_hgar build

export_eboot_trans:
	@echo "Generating EBOOT translation binary..."
	uv run -m app.elf_patch.patcher -t ./temp/downloads/eboot_trans.json -o ./build/EBTRANS.BIN

### Generate Plugin
plugin:
	@echo "Building plugin..."
	make -C plugin
	@echo "Copying plugin to build directory..."
	@mkdir -p build
	@cp -r plugin/EBOOT.BIN build/

pgftool:
	@echo "Building pgftool..."
	make -C third_party/pgftool
	@echo "Copying pgftool to build directory..."
	@mkdir -p build/tools
	@cp third_party/pgftool/dump_pgf third_party/pgftool/mix_pgf third_party/pgftool/ttf_pgf build/tools/

pspdecrypt:
	@echo "Building pspdecrypt..."
	make CC=gcc CXX=g++ -C third_party/pspdecrypt
	@echo "Copying pspdecrypt to build directory..."
	@mkdir -p build/tools
	@cp third_party/pspdecrypt/pspdecrypt build/tools/

# TODO: Deal with ISO File Injection & Patch Generation

extract:
	@echo "Extracting game files..."
	uv run scripts/pack/unpack.py -o '$(TEMP_DIR)/ULJS00064' '$(TEMP_DIR)/ULJS00064.iso'

repack:
	@echo "Repacking game files into ISO..."
	uv run scripts/pack/repack.py '$(TEMP_DIR)/ULJS00064.iso' 'build/ULJS00064_patched.iso' '$(TEMP_DIR)/ULJS00064'

decrypt: pspdecrypt
	@echo "Decrypting game files..."
	./build/tools/pspdecrypt '$(TEMP_DIR)/ULJS00064/PSP_GAME/SYSDIR/EBOOT.BIN' -o 'build/BOOT.BIN'

build:
	@echo "Building app..."
	@mkdir -p build
	@cp -r app/build/* build/
	@echo "Copying translations to build directory..."
	@mkdir -p build/translations
	@cp -r data/pz_downloads/* build/translations/
	@echo "Copying assets to build directory..."
	@mkdir -p build/assets
	@cp -r assets/* build/assets/
	@echo "Build complete."