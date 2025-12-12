# Temporary working directory
TEMP_DIR := temp
# Directory for downloaded translation files (from ParaTranz)
DOWNLOAD_DIR := $(TEMP_DIR)/downloads
# Path to the PSP_GAME directory
PSP_GAME_DIR := $(TEMP_DIR)/ULJS00064/PSP_GAME

EXPORT_GAME_DIR := build/ULJS00064/PSP_GAME
EXPORT_BIN_DIR := build/bin

EXPORT_SYSDIR := $(EXPORT_GAME_DIR)/SYSDIR
EXPORT_USRDIR := $(EXPORT_GAME_DIR)/USRDIR

# TODO: Work Folder

# USRDIR Directories
USRDIR := ${PSP_GAME_DIR}/USRDIR
BTDEMO_DIR := ${USRDIR}/btdemo
BTFACE_DIR := ${USRDIR}/btface
BTL_DIR := ${USRDIR}/btl
CHARA_DIR := ${USRDIR}/chara
EVENT_DIR := ${USRDIR}/event
FACE_DIR := ${USRDIR}/face
FREE_DIR := ${USRDIR}/free
GAME_DIR := ${USRDIR}/game
IM_DIR := ${USRDIR}/im
MAP_DIR := ${USRDIR}/map

init_db:
	@echo "Initializing database..."
	uv run -m app.cli.main --init_db

### Import Game Files
import_hgar: import_btdemo import_btface import_btl import_chara import_event import_face import_free import_game import_im import_map

import_btdemo:
	@echo "Importing btdemo hgar..."
	uv run -m app.cli.main --import_har '$(BTDEMO_DIR)'

import_btface:
	@echo "Importing btface hgar..."
	uv run -m app.cli.main --import_har '$(BTFACE_DIR)'

import_btl:
	@echo "Importing btl hgar..."
	uv run -m app.cli.main --import_har '$(BTL_DIR)'

import_chara:
	@echo "Importing chara hgar..."
	uv run -m app.cli.main --import_har '$(CHARA_DIR)'

import_event:
	@echo "Importing event hgar..."
	uv run -m app.cli.main --import_har '$(EVENT_DIR)'

import_face:
	@echo "Importing face hgar..."
	uv run -m app.cli.main --import_har '$(FACE_DIR)'

import_free:
	@echo "Importing free hgar..."
	uv run -m app.cli.main --import_har '$(FREE_DIR)'

import_game:
	@echo "Importing game hgar..."
	uv run -m app.cli.main --import_har '$(GAME_DIR)'

import_im:
	@echo "Importing im hgar..."
	uv run -m app.cli.main --import_har '$(IM_DIR)'

import_map:
	@echo "Importing map hgar..."
	uv run -m app.cli.main --import_har '$(MAP_DIR)' 

import_text:
	@echo "Importing text entries..."
	uv run -m app.cli.main --import_text '${PSP_GAME_DIR}/USRDIR/free/f2info.bin'
	uv run -m app.cli.main --import_text '${PSP_GAME_DIR}/USRDIR/free/f2tuto.bin'

import_bind:
	@echo "Importing binding entries..."
	uv run -m app.cli.main --import_bind '${PSP_GAME_DIR}/USRDIR/btl/btimtext.bin'
	uv run -m app.cli.main --import_bind '${PSP_GAME_DIR}/USRDIR/game/imtext.bin'

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
	@echo "Checking UTF8 translations..."
	uv run -m scripts.check '$(DOWNLOAD_DIR)/utf8/free/info.json' build/info_report.json evs
	uv run -m scripts.check '$(DOWNLOAD_DIR)/utf8/free/tuto.json' build/tuto_report.json evs
	uv run -m scripts.check '$(DOWNLOAD_DIR)/utf8/game/btimtext.json' build/btimtext_report.json evs
	uv run -m scripts.check '$(DOWNLOAD_DIR)/utf8/game/imtext.json' build/imtext_report.json evs

import_translations:
	@echo "Importing translations..."
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/evs_trans.json'
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/utf8/free/info.json'
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/utf8/free/tuto.json'
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/utf8/game/btimtext.json'
	uv run -m app.cli.main --import_translation '$(DOWNLOAD_DIR)/utf8/game/imtext.json'

import_images:
	@echo "Importing images..."
	uv run -m app.cli.main --import_images 'resources/trans_pic/trans'

### Export Game Files
export_text:
	@echo "Exporting text entries..."
	uv run -m app.cli.main --export_text ${EXPORT_USRDIR}/free --text_filename f2info.bin
	uv run -m app.cli.main --export_text ${EXPORT_USRDIR}/free --text_filename f2tuto.bin

export_bind:
	@echo "Exporting binding entries..."
	uv run -m app.cli.main --export_bind ${EXPORT_USRDIR}/btl --bind_filename btimtext.bin
	uv run -m app.cli.main --export_bind ${EXPORT_USRDIR}/game --bind_filename imtext.bin

export_hgar:
	@echo "Generating hgar..."
	uv run -m app.cli.main --output_hgar ${EXPORT_USRDIR}

export_eboot_trans:
	@echo "Generating EBOOT translation binary..."
	mkdir -p ${EXPORT_BIN_DIR}
	uv run -m app.elf_patch.patcher -t ${DOWNLOAD_DIR}/eboot_trans.json -o ${EXPORT_BIN_DIR}/EBTRANS.BIN

### Generate Plugin
plugin:
	@echo "Building plugin..."
	make -C plugin
	@echo "Copying plugin to build directory..."
	@mkdir -p ${EXPORT_SYSDIR}
	@cp -r plugin/EBOOT.BIN ${EXPORT_SYSDIR}/EBOOT.BIN

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
	./build/tools/pspdecrypt '${PSP_GAME_DIR}/SYSDIR/EBOOT.BIN' -o '${EXPORT_SYSDIR}/BOOT.BIN'

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