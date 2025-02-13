# make -f krkrtool.mk CXX=/opt/llvm-mingw/bin/i686-w64-mingw32-clang++ # llvm 18.1.8
# make -f krkrtool.mk CXX=i686-w64-mingw32-gcc++ # gcc 12

CXX:=clang++
BUILD_DIR:=asset/build
INCS:=-Isrc/compat
LIBS:=-lgdi32
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

ifneq (,$(findstring clang++, $(CXX))) # for llvm-mingw
CFLAGS+=-m32 -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lunwind \
	-Wl,--no-whole-archive \
	-gcodeview -Wl,--pdb=$(BUILD_DIR)/version.pdb 
LDFLAGS+= -Wl,--gc-sections
else ifneq (,$(findstring g++, $(CXX))) # for mingw-w64
CFLAGS+=-m32
LDFLAGS+= -Wl,--gc-sections \
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CXX))) # for tcc
$(error not support tcc for compile cpp)
CFLAGS+=-m32
else # for previous llvm clang with msvc
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF # for llvm
endif

all: prepare krkr_hxv4_dumphash krkr_hxv4_patch

prepare:
	@mkdir -p $(BUILD_DIR)

krkr_hxv4_dumphash: src/krkr_hxv4_dumphash.cpp src/compat/tp_stub.cpp src/compat/winversion_v100.def
	@echo "## $@"
	$(CXX) -shared  $^ -o$(BUILD_DIR)/version.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	@cp -f $(BUILD_DIR)/version.dll $(BUILD_DIR)/$@.dll
	@if [ -f $(BUILD_DIR)/version.pdb ]; then cp -f $(BUILD_DIR)/version.pdb $(BUILD_DIR)/$@.pdb; fi
	@rm -rf $(BUILD_DIR)/version.*

krkr_hxv4_patch: src/krkr_hxv4_patch.cpp src/compat/tp_stub.cpp src/compat/winversion_v100.def
	@echo "## $@"
	$(CXX) -shared  $^ -o$(BUILD_DIR)/version.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	@cp -f $(BUILD_DIR)/version.dll $(BUILD_DIR)/$@.dll
	@if [ -f $(BUILD_DIR)/version.pdb ]; then cp -f $(BUILD_DIR)/version.pdb $(BUILD_DIR)/$@.pdb; fi
	@rm -rf $(BUILD_DIR)/version.*

.PHONY: prepare krkr_hxv4_dumphash krkr_hxv4_patch