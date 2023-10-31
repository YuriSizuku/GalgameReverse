BUILD_DIR:=asset/build
INCS:=
LIBDIRS:=
LIBS:=-luser32 -lgdi32
CFLAGS:=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE # -D_DEBUG  -g

all: sdhime_krkrpatch sdhime_xp3enc

sdhime_krkrpatch: src/sdhime_krkrpatch.c
	clang -shared $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS)  $^ -o $(BUILD_DIR)/$@.dll -Os
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

sdhime_xp3enc: src/sdhime_xp3enc.cpp
	clang -shared $^ -o $(BUILD_DIR)/$@.dll $(CFLAGS) -Wl,"/DEF:src/sdhime_xp3enc.def"
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: sdhime_krkrpatch, sdhime_xp3enc