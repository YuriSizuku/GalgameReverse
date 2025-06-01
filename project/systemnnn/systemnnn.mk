# make -f systemnnn.mk CC=/opt/llvm-mingw/bin/i686-w64-mingw32-clang # llvm 18.1.8
# make -f systemnnn.mk CC=i686-w64-mingw32-gcc # gcc 12

CC:=clang
BUILD_DIR:=asset/build
INCS:=-Isrc/compat
LIBS:=-luser32 -lgdi32 -lshlwapi -ladvapi32 -lpsapi
CFLAGS:=-ffunction-sections -fdata-sections
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif
ifneq (,$(wildcard src/compat/*))
CFLAGS+=-DUSECOMPAT
endif

ifneq (,$(findstring clang, $(CC))) # for llvm-mingw
CFLAGS+=-m32
ifndef NOPDB
CFLAGS+=-gcodeview -Wl,--pdb=$(BUILD_DIR)/systemnnn_patch.pdb 
endif
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

all: prepare systemnnn_patch

prepare:
	@mkdir -p $(BUILD_DIR)

systemnnn_patch: src/systemnnn_patch.c
	@echo "## $@"
	$(CC) -shared  $^ -o $(BUILD_DIR)/$@.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) 
	@rm -rf $(BUILD_DIR)/$@.exp
	@rm -rf $(BUILD_DIR)/$@.lib
	@rm -rf $(BUILD_DIR)/$@.def

.PHONY: prepare systemnnn_patch