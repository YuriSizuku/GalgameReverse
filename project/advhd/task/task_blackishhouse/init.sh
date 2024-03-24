extract_pna() {
    indir=$1
    outdir=$2
    echo "## extract_pna $indir -> $outdir"
    
    for infile in $(ls $indir/*.pna); do
        inname=$(basename -s ".pna" $infile)
        echo $inname.pna
        mkdir -p $outdir/$inname
        python -B ${SRC_DIR}/advhd_pna.py e $infile $outdir/$inname
    done
}

extract_ws2() {
    indir=$1
    outdir=$2
    echo "## extract_ws2 $indir -> $outdir"

    for infile in $(ls $indir/*.ws2); do
        inname=$(basename $infile)
        echo $inname
        python -B ${SRC_DIR}/advhd_ws2.py e $infile $outdir/$inname.txt
    done
}

extract_lua() {
    indir=$1
    outdir=$2
    echo "## extract_lua $indir -> $outdir"

    for infile in $(ls $indir/*.lua); do
        inname=$(basename $infile)
        echo $inname
        python -B ${SRC_DIR}/compat/libtext_v610.py extract \
             $infile -o $outdir/$inname.txt -e sjis --has_cjk --min_len 2
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
        7z e ${GAME_FILE%} */Rio*.arc -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */Script.arc -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */SysGraphic.arc -o${WORK_DIR}/1.origin
    fi

    if ! [ -d ${WORK_DIR}/2.pre ]; then
        echo "## init_workdir 2.pre"
        mkdir -p ${WORK_DIR}/2.pre
        arcs=$(find ${WORK_DIR}/1.origin -type f -name *.arc -exec basename -s .arc {} \;|sort)
        cd ${WORK_DIR}/2.pre &&  mkdir -p $arcs && cd -
        
        # extract arcs
        for name in $arcs; do
            echo $name.arc
            python -B ${SRC_DIR}/advhd_arcv2.py e \
                ${WORK_DIR}/1.origin/$name.arc ${WORK_DIR}/2.pre/$name
        done
    fi

    if ! [ -d ${WORK_DIR}/3.edit ]; then
        # not all files are avialable, you must check it manually
        echo "## init_workdir 3.edit"
        mkdir -p ${WORK_DIR}/3.edit
        mkdir -p ${WORK_DIR}/3.edit/Rio_ftext
        mkdir -p ${WORK_DIR}/3.edit/Rio_ftext2
        mkdir -p ${WORK_DIR}/3.edit/Rio2_ftext
        mkdir -p ${WORK_DIR}/3.edit/Rio3_ftext
        mkdir -p ${WORK_DIR}/3.edit/Script_ftext # this should be manully extract and filter fault sentense
        mkdir -p ${WORK_DIR}/3.edit/SysGraphic_png
        
        extract_ws2 ${WORK_DIR}/2.pre/Rio ${WORK_DIR}/3.edit/Rio_ftext
        extract_ws2 ${WORK_DIR}/2.pre/Rio2 ${WORK_DIR}/3.edit/Rio2_ftext
        extract_ws2 ${WORK_DIR}/2.pre/Rio3 ${WORK_DIR}/3.edit/Rio3_ftext
        # extract_lua ${WORK_DIR}/2.pre/Script ${WORK_DIR}/3.edit/Script_ftext
        extract_pna ${WORK_DIR}/2.pre/SysGraphic ${WORK_DIR}/3.edit/SysGraphic_png
    fi

    if ! [ -d ${WORK_DIR}/4.post ]; then
        echo "## init_workdir 4.post"
        mkdir -p ${WORK_DIR}/4.post
        arcs=$(find ${WORK_DIR}/1.origin -type f -name *.arc -exec basename -s .arc {} \;|sort)
        cd ${WORK_DIR}/4.post &&  mkdir -p $arcs && cd -
    fi

    if ! [ -d ${WORK_DIR}/5.result ]; then
        echo "## init_workdir 5.result"
        mkdir -p ${WORK_DIR}/5.result
        mkdir -p ${WORK_DIR}/5.result/override
    fi
}

$* # to call function outside script