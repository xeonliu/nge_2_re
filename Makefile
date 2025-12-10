DOWNLOAD_DIR := temp/downloads # Directory for downloaded translation files (from ParaTranz)
PSP_GAME_DIR := temp/PSP_GAME # Path to the PSP_GAME directory

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

### Generate Plugin
plugin:
	@echo "Building plugin..."
	make -C plugin
	@echo "Copying plugin to build directory..."
	@mkdir -p build
	@cp -r plugin/EBOOT.BIN build/

# TODO: Deal with ISO File Injection & Patch Generation

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