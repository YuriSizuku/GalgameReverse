CC:=clang
BUILD_DIR:=./build
INCS:=-I./../../util/include -I./../../thirdparty/include -I./../../src/dvfs
LIBDIRS:=-L./../../thirdparty/lib32
LIBS:=-luser32 -lgdi32 -lshlwapi -lkernel32
CFLAGS:=-ffunction-sections -fdata-sections
LDFLAGS:=

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-O3
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
else
LIBS+=kernel32.def
endif
endif

all: aikimi_patch \
	aikimi_loader_seh \
	aikimi_chs

aikimi_patch: aikimi_patch.c
	$(CC) -shared $^ -o $(BUILD_DIR)/$@.dll \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)  
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

# this may be seemed as virus
aikimi_loader_seh: aikimi_loader_seh.c
	$(CC) $^ -o $(BUILD_DIR)/$@.exe \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)

aikimi_chs: aikimi_loader.c
	$(CC) $^ -o $(BUILD_DIR)/$@.exe -ldetours \
		$(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS)

.PHONY: aikimi_patch aikimi_chs