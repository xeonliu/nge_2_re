TARGET = patcher
OBJS = src/patcher/gb2312.o src/patcher/patcher.o src/patcher/main.o src/patcher/transform.o

INCDIR = include
CFLAGS = -O2 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS)

LIBS = 
PRX_EXPORTS = exports.exp
BUILD_PRX = 1

LDFLAGS = -nostartfiles
# GB_2312.bin: 
# 	python3 generate.py

# gb2312.c: GB_2312.bin
# 	xxd -i GB_2312.bin > gb2312.c

# gb2312.o: gb2312.c
# 	$(CC) $(CFLAGS) -c gb2312.c

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak