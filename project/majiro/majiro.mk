CC:=clang
BUILD_DIR:=./asset/build
INCS:=-I./src/compat
LIBDIRS:=-L./compat
LIBS:=-luser32 -lgdi32 -lshlwapi -ladvapi32 -lpsapi
CFLAGS:=-ffunction-sections -fdata-sections
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif

ifneq (,$(findstring clang, $(CC))) # for llvm-mingw
CFLAGS+=-m32 -gcodeview -Wl,--pdb=$(BUILD_DIR)/majiro_patch.pdb 
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

all: majiro_patch

majiro_patch: src/majiro_patch.c
	$(CC) -shared  $^ -o $(BUILD_DIR)/$@.dll \
	    -D USE_COMPAT \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) 
	@rm -rf $(BUILD_DIR)/$@.exp
	@rm -rf $(BUILD_DIR)/$@.lib
	@rm -rf $(BUILD_DIR)/$@.def

.PHONY: majiro_patch