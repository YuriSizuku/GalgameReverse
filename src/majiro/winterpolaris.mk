# use clang because of detours and naked asm
CC:=clang
# change this to your mingw32 dir
MINGW_DIR:= D:/AppExtend/EVAPORATE/msys2/mingw32
BUILD_DIR:=./build
INCS:=-I./../../util/include -I./../../thirdparty/include
LIBDIRS:=-L./../../thirdparty/lib32 -L$(MINGW_DIR)/lib
LIBS:=-ldetours -luser32 -lgdi32 # -lregex change the name libregex.dll.a to regex.lib, but it need correspond dll
CFLAGS:=-target i686-pc-windows-msvc -D _CRT_SECURE_NO_DEPRECATE -DBINTEXT_NOREGEX -D_DEBUG # -g

all: prepare winterpolaris_patch

prepare:
	if ! [ -d $(BUILD_DIR) ]; then mkdir $(BUILD_DIR);fi

clean:
	rm -rf $(BUILD_DIR)/*

# deprecated 
# $(BUILD_DIR)/binary_text.o: ./../../script/binary_text.c
# 	$(CC) -c $^ -o $@  $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS)
 
# $(BUILD_DIR)/win_hook.o: ./../../script/windows/win_hook.c
# 	$(CC) -c $^ -o $@ -D _DETOURS $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS)

# $(BUILD_DIR)/winterpolaris_hook.o: winterpolaris_hook.c
# 	$(CC) -c $^ -o $@ $(INCS) $(CFLAGS)

# $(addprefix $(BUILD_DIR)/, binary_text.o  winterpolaris_hook.o win_hook.o)
winterpolaris_patch: winterpolaris_patch.c 
	$(CC) $^ -o $(BUILD_DIR)/$@.dll $(INCS) $(LIBDIRS) $(LIBS) $(CFLAGS) -shared
	rm -rf $(BUILD_DIR)/$@.exp
	rm -rf $(BUILD_DIR)/$@.ilk
	rm -rf $(BUILD_DIR)/$@.lib

.PHONY: prepare all clean