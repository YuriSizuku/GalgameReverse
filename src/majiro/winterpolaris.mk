# use clang because of detours and naked asm
CC:=clang
BUILD_DIR:=./build
INCS:=-I./../../util/include -I./../../thirdparty/include
LIBDIRS:=-L./../../thirdparty/lib32
LIBS:=-luser32 -lgdi32
CFLAGS:=-ffunction-sections -fdata-sections
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif

ifneq (,$(findstring clang, $(CC)))
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF
else 
CFLAGS+=-m32
ifneq (,$(findstring gcc, $(CC)))
LDFLAGS+=-Wl,--gc-sections\
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive\
	-masm intel
endif
endif

all: prepare winterpolaris_patch

prepare:
	if ! [ -d $(BUILD_DIR) ]; then mkdir $(BUILD_DIR);fi

clean:
	rm -rf $(BUILD_DIR)/*
	
winterpolaris_patch: winterpolaris_patch.c 
	$(CC) $^ -o $(BUILD_DIR)/$@.dll $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) -shared
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.ilk
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: prepare all clean