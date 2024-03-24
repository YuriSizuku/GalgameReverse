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
	
init_workdir init_gamedir:
	@./init.sh $@

build_1ws2 build_1lua build_2pna build_3arcv2 build_4dll build_4exe: init_workdir
	@./build.sh $@

release_patch:
	@./build.sh $@

run:
	@cd $(GAME_DIR);$(GAME_EXEC) AdvHD_chs.exe

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