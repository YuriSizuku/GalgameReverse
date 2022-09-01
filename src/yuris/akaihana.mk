BUILD_DIR:=./build
INCS:=
LIBDIRS:=-L./../../thirdparty/lib32
LIBS:=-luser32 -lgdi32
CFLAGS:=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE \
		-ffunction-sections -fdata-sections -D_DEBUG -g
LDFLAGS:=-Wl,/OPT:REF

all: akaihana_patch

akaihana_patch: akaihana_patch.c
	clang -shared $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) $(LDFLAGS) $^ -o $(BUILD_DIR)/$@.dll -Os
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: akaihana_patch