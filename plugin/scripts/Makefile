GB2312_CUSTOM.BIN: 
	uv run gentable.py

gb2312.c: GB2312_CUSTOM.BIN
	xxd -i GB2312_CUSTOM.BIN > gb2312.c

atlas.c: atlas.bin
	xxd -i atlas.bin > atlas.c

atlas_palette.c: atlas_palette.bin
	xxd -i atlas_palette.bin > atlas_palette.c