TARGET = EBOOT
ATTR = BIN

OBJS = loader.o ../patcher.o ../gb2312.o ../transform.o

CFLAGS = -O2 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
LDFLAGS = -nostartfiles

INCDIR = ../../include

# USE_KERNEL_LIBS=1

BUILD_PRX = 1
PRX_EXPORTS=exports_loader.exp

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak