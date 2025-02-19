# make -f krkrtool.mk CC=/opt/llvm-mingw/bin/i686-w64-mingw32-clang++ # llvm 18.1.8
# make -f krkrtool.mk CC=i686-w64-mingw32-gcc++ # gcc 12

CC:=clang
BUILD_DIR:=asset/build
INCS:=-Isrc/compat
LIBS:=-luser32 -lgdi32 -lshlwapi -ladvapi32
CFLAGS:=-ffunction-sections -fdata-sections -Wno-null-dereference
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
CFLAGS+=-m32 \
	-Wl,-Bstatic,--whole-archive -lunwind \
	-Wl,--no-whole-archive \
	-gcodeview -Wl,--pdb=$(BUILD_DIR)/version.pdb 
LDFLAGS+= -Wl,--gc-sections
else ifneq (,$(findstring gcc, $(CC))) # for mingw-w64
CFLAGS+=-m32
LDFLAGS+= -Wl,--gc-sections \
	-static-libgcc \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CC))) # for tcc
CFLAGS+=-m32
else # for previous llvm clang with msvc
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF # for llvm
endif

all: prepare iwaihime_sn iwaihime_patch

prepare:
	@mkdir -p $(BUILD_DIR)

iwaihime_sn: src/iwaihime_sn.c
	@echo "## $@"
	$(CC)  $^ -o$(BUILD_DIR)/$@.exe \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	@if [ -f $(BUILD_DIR)/version.pdb ]; then cp -f $(BUILD_DIR)/version.pdb $(BUILD_DIR)/$@.pdb; fi
	@rm -rf $(BUILD_DIR)/version.*

iwaihime_patch: src/iwaihime_patch.c src/compat/winversion_v100.def
	@echo "## $@"
	$(CC) -shared  $^ -o$(BUILD_DIR)/version.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	@cp -f $(BUILD_DIR)/version.dll $(BUILD_DIR)/$@.dll
	@if [ -f $(BUILD_DIR)/version.pdb ]; then cp -f $(BUILD_DIR)/version.pdb $(BUILD_DIR)/$@.pdb; fi
	@rm -rf $(BUILD_DIR)/version.*

.PHONY: prepare iwaihime_sn iwaihime_patch