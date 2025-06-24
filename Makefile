DOWNLOAD_DIR := temp/downloads

download_translations:
	@echo "Downloading translations..."
	@mkdir -p $(DOWNLOAD_DIR)
	uv run src/scripts/paratranz/download.py  --dest_folder $(DOWNLOAD_DIR)

check_translations: $(DOWNLOAD_DIR)/evs_trans.json
	@echo "Checking EVS translations..."
	export PYTHONPATH=$(shell pwd)/src && uv run -m scripts.check '$(DOWNLOAD_DIR)/evs_trans.json' build/evs_report.json evs
	@echo "Checking EBOOT translations..."
	export PYTHONPATH=$(shell pwd)/src && uv run -m scripts.check '$(DOWNLOAD_DIR)/eboot_trans.json' build/eboot_report.json eboot

import_translations:
	@echo "Importing translations..."
	export PYTHONPATH=$(shell pwd)/src && uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/evs_trans.json'

# TODO: 修改EBOOT？
# 创建 Len Offset 之类的文件，让Plugin读取

hgar:
	@echo "Generating hgar..."

plugin:
	@echo "Building plugin..."
	make -C plugin
	@echo "Copying plugin to build directory..."
	@mkdir -p build
	@cp -r plugin/build/* build/

# TODO: Build? Install?
# 拷贝到插件目录
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