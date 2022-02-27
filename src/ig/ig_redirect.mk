CC := clang
UTILDIR := ./../../util/include
INCS = -I${UTILDIR}
LIBS = -luser32
CFLAGS = $(INCS) $(LIBS) -std=c99 -target i686-pc-windows-msvc\
		-D_WIN32 -D _CRT_SECURE_NO_DEPRECATE\
		-ffunction-sections -fdata-sections
LDFLAGS:=-Wl,/OPT:REF
# SRCS =  $(UTILDIR)/win_hook.c ig_redirect.c
# OBJS = win_hook.o ig_redirect.o
# OBJS_DEBUG =  $(addprefix ./debug/,$(OBJS))
# OBJS_RELEASE = $(addprefix ./release/,$(OBJS))

all: prepare debug release 

prepare: 
	if ! [ -d "./debug" ]; then mkdir ./debug; fi
	if ! [ -d "./release" ]; then mkdir ./release; fi

$(UTILDIR)/%.c: $(UTILDIR)/%.h

$(UTILDIR)/%.cpp: $(UTILDIR)/%.hpp


debug: ig_redirect.c
	$(CC) -shared  $^ -o ./$@/ig_redirect.dll $(CFLAGS) $(LDFLAGS) -g -D_DEBUG
	rm -rf ./$@/*.exp ./$@/*.lib

release: ig_redirect.c
	$(CC) -shared  $^ -o ./$@/ig_redirect.dll $(CFLAGS) $(LDFLAGS) -Os
	rm -rf ./$@/*.exp ./$@/*.lib

clean:
	rm -rf ./debug
	rm -rf ./release

.PHONY: all debug release prepare clean