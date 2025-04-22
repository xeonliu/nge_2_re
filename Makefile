download_translations:
	@echo "Downloading translations..."
	@mkdir -p data/pz_downloads
	python -m paratranz.download

check_translations:
	@echo "Checking translations..."
	python -m paratranz.check

import_translations:
	@echo "Importing translations..."
	python -m app.app --import_translation './downloads/evs_trans.json'

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