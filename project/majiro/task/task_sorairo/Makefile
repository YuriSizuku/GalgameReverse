# required variables: 
# WORK_DIR, build workflow dir
# SRC_DIR, project src dir, usually ../../src
# TOOL_DIR, external tool dir, usually ../../tool

# optional variables
# BASE_DIR, project basedir
# GAME_EXEC, use which command to launch game
# GAME_FILE, origin game package path
# GAME_DIR, game dir for testing

# usage: 
# in linux, "source ./_env.sh"
# in windows, "msys2_shell -here -no-start -defterm -full-path" to activate, then "source ./_env.sh"

# _env.sh example
# export GAME_NAME=Sorairo
# export GAME_ID=vndb-v1914
# if [ -n "$(uname -a | grep Msys)" ]; then
#     export BASE_DIR=/d/Downloads/$GAME_NAME
#     export GAME_EXEC=start
# else
#     LOCPATH=~/.wine/locale
#     if ! [ -d $LOCPATH/zh_CN.UTF-8 ]; then
#         mkdir -p $LOCPATH
#         localedef -f UTF-8 -i zh_CN $LOCPATH/zh_CN.UTF-8
#     fi
#     export BASE_DIR=~/Downloads/$GAME_NAME
#     export GAME_EXEC=LOCPATH=$LOCPATH\ LANG=zh_CN.UTF-8\ wine
# fi
# export GAME_FILE=$BASE_DIR/${GAME_ID}.7z
# export GAME_DIR=$BASE_DIR/${GAME_ID}_rebuild
# export WORK_DIR=$BASE_DIR/workflow
# export SRC_DIR=../../src
# export TOOL_DIR=../../tool

all: 
	@echo build Sorairo chspatch
	@make build_1mjo
	@make build_2arc
	@make build_3dll
	@make build_3exe

link:
	@if ! [ -d workflow ]; then \
        ln -s $(WORKFLOW_DIR) workflow;\
    fi

unlink:
	@rm -rf workflow
	
init_workdir init_gamedir:
	@./init.sh $@

build_1mjo build_2arc build_3dll build_3exe: init_workdir
	@./build.sh $@

release_patch:
	@./build.sh $@

run:
	@cd $(GAME_DIR);$(GAME_EXEC) sorairo_chs.exe

# vscode launch.json config
# can not pause while running, can only set breakpoint on pause or before launch
# "name": "linux sorairo",
# "type": "cppdbg",
# "request": "launch",
# "program": "sorairo_chs.exe",
# "args": [],
# "cwd": "~/Downloads/Sorairo/vndb-v1914_rebuild/",
# "stopAtEntry": false,
# "environment": [],
# "MIMode": "gdb",
# "miDebuggerPath": "/usr/bin/i686-w64-mingw32-gdb",
# "miDebuggerServerAddress": "localhost:1234",
run_gdbserver:
	@cd $(GAME_DIR); LOCPATH=~/.wine/locale LANG=zh_CN.UTF-8 \
		wine Z:/usr/share/win32/gdbserver.exe localhost:1234 sorairo_chs.exe

send: init_gamedir
	@cp -rf $(WORK_DIR)/5.result/* $(GAME_DIR)

test:
	@make send
	@make run

clean:
	@rm -f $(WORK_DIR)/*.7z
	@rm -rf ${WORK_DIR}/5.result

.PHONY: all link unlink \
	init_workdir init_gamedir \
	build_1mjo build_2arc build_3dll build_3exe \
	release_patch run send test clean