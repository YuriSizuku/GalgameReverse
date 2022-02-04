BUILD_DIR:=./build
INCS:=
LIBDIRS:=
LIBS:=-luser32 -lgdi32
CFLAGS:=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE # -D_DEBUG  -g

all: yuris_patch

yuris_patch: akaihana_yurispatch.c
	clang -shared $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS)  $^ -o $(BUILD_DIR)/$@.dll -Os
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: yuris_patch