extract_mjox() {
    indir=$1
    outdir=$2
    echo "## extract_mjox $indir -> $outdir"
    if [ -z "$outdir" ]; then outdir=$indir; fi
    for file in $(ls ${indir}/*.mjo); do
        inname=$(basename $file)
        echo $inname
        python -B ${SRC_DIR}/majiro_mjo.py d $file $outdir/$inname
    done
}

extract_mjil() {
    indir=$1
    outdir=$2
    echo "## extract_mjotext $indir -> $outdir"

    # mjo -> mjil
    cd $TOOL_DIR
    for file in $(ls ${indir}/*.mjo); do
        inname=$(basename $file)
        echo $inname
        python -B -m mjotool2 -G sorairo -d $file $outdir/${inname%.*}.mjil
    done
    cd -
}

extract_mjiltext() {    
    indir=$1
    outdir=$2
    echo "## extract_mjotext $indir -> $outdir"

    # mjil -> ftext
    for file in $(ls ${indir}/*.mjil); do
        inname=$(basename $file)
        echo $inname
        python -B ${SRC_DIR}/majiro_mjiltext.py e $file $outdir/${inname}.txt
    done
}

init_gamedir() {
    if ! [ -d ${GAME_DIR} ]; then
        echo "## init_gamedir ${GAME_DIR} <- ${GAME_FILE}"
        mkdir -p ${GAME_DIR}
        7z x $GAME_FILE -o${GAME_DIR}
        if [ "$(ls ${GAME_DIR} | wc -w)" -le 1 ]; then 
            _path=${GAME_DIR}/$(ls ${GAME_DIR})
            for file in $(ls $_path); do
                mv -f $_path/$file ${GAME_DIR}
            done
        fi
    fi
}

init_workdir() {
    if ! [ -d ${WORK_DIR}/1.origin ]; then
        echo "## init_workdir 1.origin"
        mkdir -p ${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */*.exe -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */scenario.arc -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */update*.arc -o${WORK_DIR}/1.origin
    fi

    if ! [ -d ${WORK_DIR}/2.pre ]; then
        echo "## init_workdir 2.pre"
        mkdir -p ${WORK_DIR}/2.pre
        mkdir -p ${WORK_DIR}/2.pre/data_cfg
        mkdir -p ${WORK_DIR}/2.pre/data_mjox
        mkdir -p ${WORK_DIR}/2.pre/data_mjov
        mkdir -p ${WORK_DIR}/2.pre/data_mjil

        # extract arc
        python -B ${SRC_DIR}/majiro_arc.py e ${WORK_DIR}/1.origin/scenario.arc ${WORK_DIR}/2.pre/data_mjox 1>/dev/null
        for file in $(ls -rt ${WORK_DIR}/1.origin/update*.arc); do
            echo $(basename $file)
            python ${SRC_DIR}/majiro_arc.py e $file ${WORK_DIR}/2.pre/data_mjox 1>/dev/null
        done
        mv -f ${WORK_DIR}/2.pre/data_mjox/*.cfg ${WORK_DIR}/2.edit/data_cfg/
        mv -f ${WORK_DIR}/2.pre/data_mjox/*.env ${WORK_DIR}/2.edit/data_cfg/
        
        # extract mjo
        extract_mjox ${WORK_DIR}/2.pre/data_mjox ${WORK_DIR}/2.pre/data_mjov
        extract_mjil ${WORK_DIR}/2.pre/data_mjox ${WORK_DIR}/2.pre/data_mjil/
    fi

    if ! [ -d ${WORK_DIR}/3.edit ]; then
        echo "## init_workdir 3.edit"
        mkdir -p ${WORK_DIR}/3.edit
        mkdir -p ${WORK_DIR}/3.edit/data_cfg
        mkdir -p ${WORK_DIR}/3.edit/data_mjil
        mkdir -p ${WORK_DIR}/3.edit/data_ftext
        mkdir -p ${WORK_DIR}/3.edit/data_png
        extract_mjiltext ${WORK_DIR}/2.pre/data_mjil/ ${WORK_DIR}/3.edit/data_ftext
    fi

    if ! [ -d ${WORK_DIR}/4.post ]; then
        echo "## init_workdir 4.post"
        mkdir -p ${WORK_DIR}/4.post
        mkdir -p ${WORK_DIR}/4.post/data_mjil
        mkdir -p ${WORK_DIR}/4.post/data_mjov
        mkdir -p ${WORK_DIR}/4.post/update
    fi

    if ! [ -d ${WORK_DIR}/5.result ]; then
        echo "## init_workdir 5.result"
        mkdir -p ${WORK_DIR}/5.result
        mkdir -p ${WORK_DIR}/5.result/override
        mkdir -p ${WORK_DIR}/5.result/override/savedata
    fi
}

$* # to call function outside script