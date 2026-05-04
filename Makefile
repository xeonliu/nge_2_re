# ==========================================
# Configuration & Path Definitions
# ==========================================
BASE_ID := 00064
GAME_ID ?= $(BASE_ID)
GAME_IDS := 00061 00064

# Temporary and Build Directories
TEMP_DIR        := temp
DOWNLOAD_DIR    := $(TEMP_DIR)/downloads
BUILD_DIR       := build

# Per-GAME_ID export directories (avoid sharing between different game IDs)
EXPORT_DIR          := $(BUILD_DIR)/ULJS$(GAME_ID)
EXPORT_GAME_DIR     := $(EXPORT_DIR)/PSP_GAME
EXPORT_BIN_DIR      := $(EXPORT_GAME_DIR)/USRDIR
EXPORT_SYSDIR       := $(EXPORT_GAME_DIR)/SYSDIR
EXPORT_USRDIR       := $(EXPORT_GAME_DIR)/USRDIR
TOOLS_DIR           := $(BUILD_DIR)/tools

# Source directories (per GAME_ID - each ISO has its own extraction)
PSP_GAME_DIR    := $(TEMP_DIR)/ULJS$(GAME_ID)/PSP_GAME
USRDIR          := $(PSP_GAME_DIR)/USRDIR

# Base export directory for copying (used when building derived IDs from base)
BASE_EXPORT_DIR := $(BUILD_DIR)/ULJS$(BASE_ID)

# HGAR Directories List (Used for loop)
HGAR_DIRS       := btdemo btface btl chara event face free game im map

# Tool Commands
UV_RUN          := uv run
PYTHON_MAIN     := $(UV_RUN) -m app.cli.main

# Timestamped output filenames to avoid overwriting previous builds (Evaluated once)
TIMESTAMP := $(shell TZ=Asia/Shanghai date +%Y%m%d-%H%M%S)
PATCHED_ISO := $(BUILD_DIR)/ULJS$(GAME_ID)_patched_$(TIMESTAMP).iso
PATCH_XDELTA := $(BUILD_DIR)/ULJS$(GAME_ID)_patch_$(TIMESTAMP).xdelta

# ==========================================
# Default Target: Help
# ==========================================
.DEFAULT_GOAL := help

help:
	@echo "Available commands:"
	@echo "  make init_db             - Initialize the database"
	@echo "  make import_all          - Import all assets (hgar, text, bind)"
	@echo "  make download_trans      - Download translations from ParaTranz"
	@echo "  make import_trans        - Import downloaded translations to DB"
	@echo "  make export_all          - Export all game files (text, hgar, eboot)"
	@echo "  make gen_metadata        - Generate patch metadata (JSON and image)"
	@echo "  make patch_iso           - Create the patched ISO and xdelta"
	@echo "  make patch_all_ids       - Generate patches for all GAME_IDS (00061 & 00064)"
	@echo "  make full_build          - Run the complete pipeline"
	@echo "  make rebuild             - Rebuild from downloaded translations"
	@echo "  make clean               - Clean build artifacts"

# ==========================================
# Database & Import Tasks
# ==========================================

init_db:
	@echo "Initializing database..."
	$(PYTHON_MAIN) --init_db

import_hgar:
	@echo "Importing HGAR archives..."
	@for dir in $(HGAR_DIRS); do \
		echo "  -> Importing $$dir..."; \
		$(PYTHON_MAIN) --import_har "$(USRDIR)/$$dir"; \
	done

import_text:
	@echo "Importing text entries..."
	$(PYTHON_MAIN) --import_text '$(USRDIR)/free/f2info.bin'
	$(PYTHON_MAIN) --import_text '$(USRDIR)/free/f2tuto.bin'

import_bind:
	@echo "Importing binding entries..."
	$(PYTHON_MAIN) --import_bind '$(USRDIR)/btl/btimtext.bin'
	$(PYTHON_MAIN) --import_bind '$(USRDIR)/game/imtext.bin'

import_all: import_hgar import_text import_bind

# ==========================================
# Translation Management
# ==========================================

download_trans:
	@echo "Downloading translations..."
	@mkdir -p $(DOWNLOAD_DIR)
	$(UV_RUN) -m scripts.paratranz.download --action download --dest_folder $(DOWNLOAD_DIR)
	$(UV_RUN) -m scripts.paratranz.download --action merge --dest_folder $(DOWNLOAD_DIR)

check_trans:
	@echo "Checking translations..."
	$(UV_RUN) -m scripts.check '$(DOWNLOAD_DIR)/evs_trans.json' $(BUILD_DIR)/evs_report.json evs

import_trans:
	@echo "Importing translations..."
	$(PYTHON_MAIN) --import_translation '$(DOWNLOAD_DIR)/evs_trans.json'
	$(PYTHON_MAIN) --import_translation '$(DOWNLOAD_DIR)/utf8/free/info.json'
	$(PYTHON_MAIN) --import_translation '$(DOWNLOAD_DIR)/utf8/free/tuto.json'
	$(PYTHON_MAIN) --import_translation '$(DOWNLOAD_DIR)/utf8/game/btimtext.json'
	$(PYTHON_MAIN) --import_translation '$(DOWNLOAD_DIR)/utf8/game/imtext.json'

import_images:
	@echo "Importing images..."
	$(PYTHON_MAIN) --import_images 'resources/trans_pic/trans'

# ==========================================
# Export Tasks
# ==========================================

export_text:
	@echo "Exporting text entries..."
	$(PYTHON_MAIN) --export_text $(EXPORT_USRDIR)/free --text_filename f2info.bin
	$(PYTHON_MAIN) --export_text $(EXPORT_USRDIR)/free --text_filename f2tuto.bin

export_bind:
	@echo "Exporting binding entries..."
	$(PYTHON_MAIN) --export_bind $(EXPORT_USRDIR)/btl --bind_filename btimtext.bin
	$(PYTHON_MAIN) --export_bind $(EXPORT_USRDIR)/game --bind_filename imtext.bin

export_hgar:
	@echo "Generating hgar..."
	$(PYTHON_MAIN) --output_hgar $(EXPORT_USRDIR)

export_eboot_trans:
	@echo "Generating EBOOT translation binary..."
	@mkdir -p $(EXPORT_BIN_DIR)
	$(UV_RUN) -m app.elf_patch.patcher -t $(DOWNLOAD_DIR)/eboot_trans.json -o $(EXPORT_BIN_DIR)/EBTRANS.BIN

export_all: export_text export_bind export_hgar export_eboot_trans

# ==========================================
# Tools & Plugins Build
# ==========================================

plugin:
	@echo "Building plugin..."
	$(MAKE) -C plugin
	@mkdir -p $(EXPORT_SYSDIR)
	@echo "Copying EBOOT.BIN to SYSDIR..."
	@cp -r plugin/EBOOT.BIN $(EXPORT_SYSDIR)/EBOOT.BIN

pgftool:
	@echo "Building pgftool..."
	$(MAKE) -C third_party/pgftool
	@mkdir -p $(TOOLS_DIR)
	@cp third_party/pgftool/{dump_pgf,mix_pgf,ttf_pgf} $(TOOLS_DIR)/

pspdecrypt:
	@echo "Building pspdecrypt..."
	$(MAKE) CC=gcc CXX=g++ -C third_party/pspdecrypt
	@mkdir -p $(TOOLS_DIR)
	@cp third_party/pspdecrypt/pspdecrypt $(TOOLS_DIR)/

# ==========================================
# ISO & Patch Operations
# ==========================================

extract_iso:
	@if [ -d '$(PSP_GAME_DIR)' ]; then \
		echo "ISO already extracted for GAME_ID=$(GAME_ID)."; \
	else \
		echo "Extracting game files (GAME_ID=$(GAME_ID))..."; \
		$(UV_RUN) scripts/pack/unpack.py -o '$(TEMP_DIR)/ULJS$(GAME_ID)' '$(TEMP_DIR)/ULJS$(GAME_ID).iso'; \
	fi

decrypt_eboot: pspdecrypt
	@echo "Decrypting EBOOT..."
	@mkdir -p $(EXPORT_SYSDIR)
	./$(TOOLS_DIR)/pspdecrypt '$(PSP_GAME_DIR)/SYSDIR/EBOOT.BIN' -o '$(EXPORT_SYSDIR)/BOOT.BIN'

copy_font:
	@echo "Copying font files..."
	@mkdir -p $(EXPORT_USRDIR)
	@cp resources/assets/fonts.pgf $(EXPORT_USRDIR)/fonts.pgf

edit_sfo:
	@echo "Editing PARAM.SFO..."
	@mkdir -p $(EXPORT_GAME_DIR)
	$(UV_RUN) -m scripts.sfo --output '$(EXPORT_GAME_DIR)/PARAM.SFO' '$(PSP_GAME_DIR)/PARAM.SFO'

gen_metadata:
	@echo "Generating patch metadata..."
	$(UV_RUN) -m scripts.gen_metadata --output $(BUILD_DIR)/metadata.json --image $(BUILD_DIR)/metadata.png --pic0 '$(PSP_GAME_DIR)/PIC0.PNG'
	@echo "Copying metadata.raw to game directory..."
	@mkdir -p $(EXPORT_BIN_DIR)
	@cp $(BUILD_DIR)/metadata.raw '$(EXPORT_BIN_DIR)/metadata.raw'

repack_iso:
	@echo "Repacking game files into ISO (GAME_ID=$(GAME_ID))..."
	@mkdir -p $(BUILD_DIR)
	$(UV_RUN) scripts/pack/repack_add.py '$(TEMP_DIR)/ULJS$(GAME_ID).iso' '$(PATCHED_ISO)' '$(EXPORT_DIR)'

gen_xdelta:
	@echo "Generating xdelta patch..."
	xdelta3 -e -9 -S djw -f -s '$(TEMP_DIR)/ULJS$(GAME_ID).iso' '$(PATCHED_ISO)' '$(PATCH_XDELTA)'

patch_iso: repack_iso gen_xdelta

# ==========================================
# Meta Targets
# ==========================================

full_build:
	@echo "Starting full build pipeline..."
	$(MAKE) init_db
	$(MAKE) extract_iso GAME_ID=$(BASE_ID)
	$(MAKE) import_all GAME_ID=$(BASE_ID)
	$(MAKE) import_images
	$(MAKE) import_trans
	$(MAKE) patch_all_ids

rebuild:
	@echo "Starting rebuild pipeline..."
	$(MAKE) download_trans
	$(MAKE) import_trans
	$(MAKE) import_images
	$(MAKE) patch_all_ids

# 严格保证基准 ID (00064) 最先构建，其余 ID 基于基准目录拷贝
patch_all_ids:
	@echo "=========================================="
	@echo "Starting patch generation for all GAME_IDs"
	@echo "=========================================="
	@$(MAKE) patch_id_$(BASE_ID)
	@for id in $(filter-out $(BASE_ID),$(GAME_IDS)); do \
		$(MAKE) patch_id_$$id; \
	done

patch_id_%:
	@echo "=========================================="
	@echo "Generating patch for GAME_ID $*..."
	@echo "=========================================="
	@if [ "$*" = "$(BASE_ID)" ]; then \
		echo "-> Building base export for $(BASE_ID)..."; \
		$(MAKE) extract_iso GAME_ID=$*; \
		$(MAKE) export_all GAME_ID=$*; \
		$(MAKE) plugin GAME_ID=$*; \
		$(MAKE) copy_font GAME_ID=$*; \
	else \
		echo "-> Copying base export ($(BASE_ID)) for $*..."; \
		mkdir -p $(BUILD_DIR)/ULJS$*; \
		cp -r $(BASE_EXPORT_DIR)/* $(BUILD_DIR)/ULJS$*/; \
		$(MAKE) extract_iso GAME_ID=$*; \
	fi
	@echo "-> Generating game-specific files for $*..."
	$(MAKE) decrypt_eboot GAME_ID=$*
	$(MAKE) edit_sfo GAME_ID=$*
	$(MAKE) gen_metadata GAME_ID=$*
	$(MAKE) repack_iso GAME_ID=$* TIMESTAMP=$(TIMESTAMP)
	$(MAKE) gen_xdelta GAME_ID=$* TIMESTAMP=$(TIMESTAMP)

clean:
	@echo "Cleaning build directory..."
	rm -rf $(BUILD_DIR)

.PHONY: help init_db import_hgar import_text import_bind import_images import_all \
        download_trans check_trans import_trans \
        export_text export_bind export_hgar export_eboot_trans export_all \
        plugin pgftool pspdecrypt \
        extract_iso decrypt_eboot copy_font repack_iso gen_xdelta gen_metadata patch_iso \
        full_build rebuild patch_all_ids patch_id_% clean