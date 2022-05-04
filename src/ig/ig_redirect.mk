CC:=clang
BUILD_DIR:=./build
INCS:=-I./../../util/include -I./../../thirdparty/include -I./../../src/dvfs
LIBDIRS:=-L./../../thirdparty/lib32
LIBS:=-luser32 -lgdi32 -lShlwapi
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
LDFLAGS+=-static-libgcc -static-libstdc++ -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive
endif
endif

all: prepare debug release 

prepare: 
	if ! [ -d "./debug" ]; then mkdir ./debug; fi
	if ! [ -d "./release" ]; then mkdir ./release; fi

debug: ig_redirect.c
	$(CC) -shared  $^ -o ./$@/ig_redirect.dll \
		$(INCS) $(LIBS) $(CFLAGS) $(LDFLAGS) -g -D_DEBUG
	rm -rf ./$@/*.exp ./$@/*.lib

release: ig_redirect.c
	$(CC) -shared  $^ -o ./$@/ig_redirect.dll \
		$(INCS) $(LIBS) $(CFLAGS) $(LDFLAGS) -Os
	rm -rf ./$@/*.exp ./$@/*.lib

clean:
	rm -rf ./debug
	rm -rf ./release

.PHONY: all debug release prepare clean