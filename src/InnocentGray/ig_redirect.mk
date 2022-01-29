CC := clang
UTILDIR := ./../../script/windows
INCS = -I${UTILDIR}
LIBS = -luser32
CFLAGS = $(INCS) $(LIBS) -std=c99 -target i686-pc-windows-msvc -D_WIN32
SRCS =  $(UTILDIR)/win_hook.c ig_redirect.c
OBJS = win_hook.o ig_redirect.o
OBJS_DEBUG =  $(addprefix ./debug/,$(OBJS))
OBJS_RELEASE = $(addprefix ./release/,$(OBJS))

all: prepare debug release 

prepare: 
	if ! [ -d "./debug" ]; then mkdir ./debug; fi
	if ! [ -d "./release" ]; then mkdir ./release; fi

$(UTILDIR)/%.c: $(UTILDIR)/%.h

$(UTILDIR)/%.cpp: $(UTILDIR)/%.hpp

./debug/win_hook.o: $(UTILDIR)/win_hook.c
	$(CC) -c $< $(CFLAGS) -o $@ -g -D_DEBUG

./debug/ig_redirect.o: ig_redirect.c
	$(CC) -c $< $(CFLAGS) -o $@ -g -D_DEBUG

./release/win_hook.o: $(UTILDIR)/win_hook.c
	$(CC) -c $< $(CFLAGS) -o $@ -Os

./release/ig_redirect.o: ig_redirect.c
	$(CC) -c $< $(CFLAGS) -o $@ -Os

debug: $(OBJS_DEBUG)
	$(CC) -shared  $^ $(CFLAGS) -o ./$@/ig_redirect.dll -Wl,"/DEF:ig_redirect.def" -g

release: $(OBJS_RELEASE)
	$(CC) -shared  $^ $(CFLAGS) -o ./$@/ig_redirect.dll -Wl,"/DEF:ig_redirect.def"

clean:
	rm -rf ./debug
	rm -rf ./release

.PHONY: all debug release prepare clean