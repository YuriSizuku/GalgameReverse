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

ifneq (,$(wildcard src/compat/dvfs/*.h))
CFLAGS+=-DUSE_DVFS
endif

CFLAGS64:=$(CFLAGS) 
ifneq (,$(findstring clang, $(CC))) # for llvm-mingw
CFLAGS+=-m32 -gcodeview -Wl,--pdb=$(BUILD_DIR)/amanomiko_patch.pdb
CFLAGS64+=m64
LDFLAGS+= -Wl,--gc-sections
else ifneq (,$(findstring gcc, $(CC))) # for mingw-w64
CFLAGS+=-m32
LDFLAGS+= -Wl,--gc-sections \
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CC))) # for tcc
CFLAGS+=-m32
CFLAGS64+=-m64
else # for previous llvm clang with msvc
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
CFLAGS64+=-target x86_64-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF
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