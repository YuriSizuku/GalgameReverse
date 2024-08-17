# make -f yuris.mk CC=/opt/llvmmingw/bin/i686-w64-mingw32-clang # llvm 18.1.8
# make -f yuris.mk CC=i686-w64-mingw32-gcc # gcc 12

CC:=clang
BUILD_DIR:=asset/build
INCS:=-Isrc/compat
LIBS:=-luser32 -lgdi32 -lshlwapi -ladvapi32 -lpsapi
CFLAGS:=-ffunction-sections -fdata-sections -Wno-format
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif
ifneq (,$(wildcard src/compat/*))
CFLAGS+=-DUSECOMPAT
endif
ifneq (,$(wildcard src/compat/dvfs/*.h))
CFLAGS+=-DUSEWINDVFS
endif

ifneq (,$(findstring clang, $(CC))) # for llvm-mingw
CFLAGS+=-m32 -gcodeview -Wl,--pdb=$(BUILD_DIR)/yuris_patch.pdb 
LDFLAGS+= -Wl,--gc-sections
else ifneq (,$(findstring gcc, $(CC))) # for mingw-w64
CFLAGS+=-m32
LDFLAGS+= -Wl,--gc-sections \
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CC))) # for tcc
CFLAGS+=-m32
else # for previous llvm clang with msvc
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF # for llvm
endif

all: prepare yuris_patch

prepare:
	@mkdir -p $(BUILD_DIR)

yuris_patch: src/yuris_patch.c
	@echo "## $@"
	$(CC) -shared  $^ -o $(BUILD_DIR)/$@.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) 
	@rm -rf $(BUILD_DIR)/$@.exp
	@rm -rf $(BUILD_DIR)/$@.lib
	@rm -rf $(BUILD_DIR)/$@.def

.PHONY: prepare yuris_patch