LIBPREFIX?=./../../../
ARCH?=i686
PREFIX?=./../../bin

CC:=clang
INCS:=-I$(LIBPREFIX)util/include
LIBDIRS:=
LIBS:=-luser32 -lgdi32
CFLAGS:=-ffunction-sections -fdata-sections -std=c99
LDFLAGS:=-Wl,/OPT:REF

ifeq ($(ARCH), x86_64) 
LIBDIRS+=-L$(LIBPREFIX)thirdparty/lib64
CFLAGS+=-D_WIN64
ifdef DEBUG
ARCH_POSTFIX:=64d
else
ARCH_POSTFIX:=64
endif 
else
LIBDIRS+=-L$(LIBPREFIX)thirdparty/lib32
ifdef DEBUG
ARCH_POSTFIX:=32d
else
ARCH_POSTFIX:=32
endif 
endif

ifneq (,$findstring(clang, $(CC)))
CFLAGS+=-target $(ARCH)-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE 
endif 

ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif 
LIBDIRS+=-L$(PREFIX) 

ifeq ($(shell echo ${OS}), Windows_NT)
DLL_EXT=.dll
EXE_EXT=.exe
else
DLL_EXT?=.so
EXE_EXT?=
endif

all: prepare\
	libwinpe\
	win_injectmemdll_shellcodestub\
	win_injectmemdll

clean:
	rm -rf $(PREFIX)/*libwinpe*
	rm -rf $(PREFIX)/*win_injectmemdll*

prepare:
	@if ! [ -d $(PREFIX) ]; then mkdir -p $(PREFIX); fi

libwinpe: libwinpe.c
	@echo \#\#building $@ ...
	$(CC) $< -o $(PREFIX)/$@$(ARCH_POSTFIX)$(DLL_EXT) \
		-shared $(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)
	rm -rf $(PREFIX)/*.exp

win_injectmemdll_shellcodestub: win_injectmemdll.c libwinpe
	python $@.py $< $(PREFIX)/libwinpe$(ARCH_POSTFIX)$(DLL_EXT) $(PREFIX)/_$<

win_injectmemdll: win_injectmemdll_shellcodestub libwinpe
	@echo \#\#building $@ ...
	$(CC) $(PREFIX)/_$@.c -o $(PREFIX)/$@$(ARCH_POSTFIX)$(EXE_EXT)\
		-llibwinpe$(ARCH_POSTFIX) \
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)
	rm -rf $(PREFIX)/_$<

.PHONY: all clean prepare libwinpe win_injectmemdll