# as the inline asm, only clang and msvc are supported
CC:=clang
BUILD_DIR:=./asset/build
INCS:=-Isrc/compat
LIBDIRS:=-Lsrc/compat
LIBS:=-luser32 -lgdi32 -lshlwapi
CFLAGS:=-ffunction-sections -fdata-sections
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif

ifdef USE_DVFS
CFLAGS+=-DUSE_DVFS
endif

CFLAGS64:=$(CFLAGS) 
ifneq (,$(findstring clang, $(CC)))
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
CFLAGS64+=-target x86_64-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF
else 
CFLAGS+=-m32
CFLAGS64+=-m64
ifneq (,$(findstring gcc, $(CC)))
LDFLAGS+= -Wl,--gc-sections\
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
endif
endif

all: amanomiko_patch 

amanomiko_patch: src/amanomiko_patch.c
	$(CC) -shared  $^ -o $(BUILD_DIR)/$@.dll \
	    -DUSE_COMPAT \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) 
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

liblzss20_64: src/liblzss20.c
	$(CC) -shared $^ -o src/$@.dll \
	    -DUSE_COMPAT \
	    $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS64) $(LDFLAGS) 
	rm -rf src/$@.exp
	rm -rf src/$@.lib
	rm -rf src/$@.pdb

.PHONY: amanomiko_patch liblzss20_64