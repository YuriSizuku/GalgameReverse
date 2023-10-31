# as the inline asm, only clang and msvc are supported
CC:=clang
BUILD_DIR:=./asset/build
INCS:=-I./src/compat
LIBDIRS:=-L./src/compat
LIBS:=-luser32 -lgdi32 -lshlwapi
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
LDFLAGS+= -Wl,--gc-sections\
	-static-libgcc -static-libstdc++ \
	-Wl,-Bstatic,--whole-archive -lwinpthread \
	-Wl,--no-whole-archive
endif
endif

all: soraironoorgan_patch

soraironoorgan_patch: src/soraironoorgan_patch.c
	$(CC) -shared  $^ -o $(BUILD_DIR)/$@.dll -D USE_COMPAT \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) 
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: soraironoorgan_patch