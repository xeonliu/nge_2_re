GB2312_CUSTOM.BIN: 
	uv run gentable.py

gb2312.c: GB2312_CUSTOM.BIN
	xxd -i GB2312_CUSTOM.BIN > gb2312.c

atlas.c: atlas.bin
	xxd -i atlas.bin > atlas.c