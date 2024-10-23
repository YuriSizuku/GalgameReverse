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
# at first, put the vairable in _env.sh file
# in linux, "source ./_env.sh"
# in windows, "msys2_shell -here -no-start -defterm -full-path" to activate, then "source ./_env.sh"

# _env.sh example
# export GAME_NAME=BlackishHouse
# export GAME_ID=vndb-v17853
# if [ -n "$(uname -a | grep Msys)" ]; then
#     export BASE_DIR=/d/Downloads/$GAME_NAME
#     export GAME_EXEC=start
# else
#     LOCPATH=~/.wine/locale
#     # zh_CN.UTF-8 not worked
#     export BASE_DIR=~/Downloads/$GAME_NAME
#     export GAME_EXEC=wine
# fi
# export GAME_FILE=$BASE_DIR/${GAME_ID}.7z
# export GAME_DIR=$BASE_DIR/${GAME_ID}_rebuild
# export WORK_DIR=$BASE_DIR/workflow
# export SRC_DIR=../../src
# export TOOL_DIR=../../tool

SHELL := /bin/bash

all: 
	@echo build BlackishHouse chspatch
	@make build_1ws2
	@make build_1lua
	@make build_2pna
	@make build_3arcv2
	@make build_4dll
	@make build_4exe

link:
	@if ! [ -d workflow ]; then \
        ln -s $(WORKFLOW_DIR) workflow;\
    fi

unlink:
	@rm -rf workflow
	
init_workdir init_gamedir init_mingwsdk:
	@./init.sh $@

build_1ws2 build_1lua build_2pna build_3arcv2 build_4dll build_4exe: init_workdir
	@./build.sh $@

release_patch:
	@./build.sh $@

run:
	@cd $(GAME_DIR);$(GAME_EXEC) AdvHD_chs.exe

# vscode launch.json config
# can not pause while running, can only set breakpoint on pause or before launch
# "name": "linux wajin_asaki",
# "type": "cppdbg",
# "request": "launch",
# "program": "AdvHD_chs.exe",
# "args": [],
# "cwd": "~/Downloads/BlackishHouse/vndb-v17853_rebuild/",
# "stopAtEntry": false,
# "environment": [],
# "MIMode": "gdb",
# "miDebuggerPath": "/usr/bin/i686-w64-mingw32-gdb",
# "miDebuggerServerAddress": "localhost:1234",
run_gdbserver:
	@cd $(GAME_DIR); LOCPATH=~/.wine/locale LANG=zh_CN.UTF-8 \
		wine Z:/usr/share/win32/gdbserver.exe localhost:1234 AdvHD_chs.exe

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
	build_1ws2 build_1lua build_2pna build_3arcv2 build_4dll build_4exe \
	release_patch run send test clean