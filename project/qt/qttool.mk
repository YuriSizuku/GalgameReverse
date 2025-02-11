# this only works for dll compiled by gcc, and not works with qtCore.dll by msvc
# as the export name format is different

# make -f qttool.mk CXX=/opt/llvm-mingw/bin/x86_64-w64-mingw32-clang++ QTSDK=/yourqtpath   # llvm 18.1.8
# make -f qttool.mk CXX=x86_64-w64-mingw32-gcc++ QTSDK=/yourqtpath # gcc 12

CXX:=clang++
QTSDK?=D:/Software/sdk/qtsdk/qt5.15
BUILD_DIR:=asset/build
INCS:=-Isrc/compat -I$(QTSDK)/include
LIBS:=-L$(QTSDK)/lib -lQt5Core
CFLAGS:=-ffunction-sections -fdata-sections -Wno-null-dereference -Wno-ignored-attributes
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
CFLAGS+=-m64
CFLAGS+=-static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lunwind \
	-Wl,--no-whole-archive \
	-gcodeview -Wl,--pdb=$(BUILD_DIR)/version.pdb 
LDFLAGS+= -Wl,--gc-sections
else ifneq (,$(findstring g++, $(CXX))) # for mingw-w64
CFLAGS+=-m64
LDFLAGS+= -Wl,--gc-sections \
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
else ifneq (,$(findstring tcc, $(CXX))) # for tcc
$(error not support tcc for compile cpp)
CFLAGS+=-m64
else # for previous llvm clang with msvc
CFLAGS+=-target x86_-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF # for llvm
endif

all: prepare qfile_dump

prepare:
	@mkdir -p $(BUILD_DIR)

qfile_dump: src/qfile_dump.cpp src/compat/winversion_v100.def
	@echo "## $@"
	$(CXX) -shared  $^ -o$(BUILD_DIR)/version.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	@cp -f $(BUILD_DIR)/version.dll $(BUILD_DIR)/$@.dll
	@if [ -f $(BUILD_DIR)/version.pdb ]; then cp -f $(BUILD_DIR)/version.pdb $(BUILD_DIR)/$@.pdb; fi
	@rm -rf $(BUILD_DIR)/version.exp
	@rm -rf $(BUILD_DIR)/version.lib
	@rm -rf $(BUILD_DIR)/version.def

.PHONY: prepare qfile_dump