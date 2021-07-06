CC := clang
UTILDIR := ./../../script/windows
INCS = -I${UTILDIR}
LIBS = -luser32
CFLAGS = $(INCS) $(LIBS) -std=c99 -target i686-pc-windows-msvc -D_WIN32
SRCS =  $(UTILDIR)/win_hook.c redirect_ig.c
OBJS = win_hook.o redirect_ig.o
OBJS_DEBUG =  $(addprefix ./debug/,$(OBJS))
OBJS_RELEASE = $(addprefix ./release/,$(OBJS))

all: prepare debug release 

prepare: 
	if NOT [ -d "./debug" ]; then mkdir ./debug; fi
	if NOT [ -d "./release" ]; then mkdir ./release; fi

$(UTILDIR)/%.c: $(UTILDIR)/%.h

$(UTILDIR)/%.cpp: $(UTILDIR)/%.hpp

./debug/win_hook.o: $(UTILDIR)/win_hook.c
	$(CC) -c $< $(CFLAGS) -o $@ -g -D_DEBUG

./debug/redirect_ig.o: redirect_ig.c
	$(CC) -c $< $(CFLAGS) -o $@ -g -D_DEBUG

./release/win_hook.o: $(UTILDIR)/win_hook.c
	$(CC) -c $< $(CFLAGS) -o $@ -Os

./release/redirect_ig.o: redirect_ig.c
	$(CC) -c $< $(CFLAGS) -o $@ -Os

debug: $(OBJS_DEBUG)
	$(CC) -shared  $^ $(CFLAGS) -o ./$@/redirect_ig.dll -Wl,"/DEF:redirect_ig.def" -g

release: $(OBJS_RELEASE)
	$(CC) -shared  $^ $(CFLAGS) -o ./$@/redirect_ig.dll -Wl,"/DEF:redirect_ig.def"

clean:
	rm -rf ./debug
	rm -rf ./release

.PHONY: all debug release prepare clean