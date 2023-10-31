CC:=clang
BUILD_DIR:=asset/build
SRC_DIR:=src
INCS:=-I$(SRC_DIR) -I$(SRC_DIR)/compat
LIBDIRS:=-I$(SRC_DIR)/compat
LIBS:=-luser32 -lgdi32 -lshlwapi -lpsapi
CFLAGS:=-ffunction-sections -fdata-sections -DUSE_COMPAT
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif

ifdef USE_WINDVFS
CFLAGS+=-DUSE_WINDVFS
endif

ifneq (,$(findstring clang, $(CC)))
CFLAGS+=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE
LDFLAGS+=-Wl,/OPT:REF
else 
CFLAGS+=-m32
ifneq (,$(findstring gcc, $(CC)))
LDFLAGS+= -Wl,--gc-sections\
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
endif
endif

all: yuris_patch

yuris_patch: $(SRC_DIR)/yuris_patch.c
	$(CC) -shared $^ -o $(BUILD_DIR)/$@.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib
	rm -rf $(BUILD_DIR)/$@.def

.PHONY: yuris_patch