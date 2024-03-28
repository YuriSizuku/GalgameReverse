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
# export GAME_NAME=WajinIbunroku
# export GAME_ID=vndb-v11340
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

all: 
	@echo build Sorairo chspatch
	@make build_1txt
	@make build_1spt
	@make build_2dwq
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

build_1txt build_1spt build_2dwq build_3dll build_3exe: init_workdir
	@./build.sh $@

release_patch:
	@./build.sh $@

run:
	@cd $(GAME_DIR);$(GAME_EXEC) wajin_asaki_chs.exe

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
	build_1txt build_1spt build_2dwq build_3dll build_3exe \
	release_patch run send test clean