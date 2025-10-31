DOWNLOAD_DIR := temp/downloads
EVENT_DIR := temp/PSP_GAME/USRDIR/event

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

import_event:
	@echo "Importing event hgar..."
	uv run -m app.cli.main --import_har '$(EVENT_DIR)'

hgar:
	@echo "Generating hgar..."
	uv run -m app.cli.main --output_hgar build

plugin:
	@echo "Building plugin..."
	make -C plugin
	@echo "Copying plugin to build directory..."
	@mkdir -p build
	@cp -r plugin/EBOOT.BIN build/

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