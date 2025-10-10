decode_fxf() {
    indir=$1
    outdir=$2
    echo "## decode_fxf $indir -> $outdir"
    if [ -z "$outdir" ]; then outdir=$indir; fi
    for infile in $(ls ${indir}/*.fxf); do
        inname=$(basename $infile)
        echo $inname
        outfile=$outdir/$inname.txt
        if [ -n "$(uname -a | grep Msys)" ]; then
            infile=$(cygpath -w $infile)
            outfile=$(cygpath -w $outfile)
        fi
        python -B -c "import sys;sys.path.append(r'$SRC_DIR');\
            import systemnnn_spt as nnn;\
            nnn.Spt.decrypt_to(r'$infile', r'$outfile')"
    done
}

encode_fxf() {
    indir=$1
    outdir=$2
    echo "## encode_fxf $indir -> $outdir"
    if [ -z "$outdir" ]; then outdir=$indir; fi
    for infile in $(ls ${indir}/*.fxf.txt); do
        inname=$(basename $infile ".txt")
        echo $inname
        outfile=$outdir/$inname
        if [ -n "$(uname -a | grep Msys)" ]; then
            infile=$(cygpath -w $infile)
            outfile=$(cygpath -w $outfile)
        fi
        python -B -c "import sys;sys.path.append(r'$SRC_DIR');\
            import systemnnn_spt as nnn;\
            nnn.Spt.encrypt_to(r'$infile', r'$outfile')"
    done
}

extract_spt() {
    indir=$1
    outdir=$2
    echo "## extract_spt $indir -> $outdir"
    if [ -z "$outdir" ]; then outdir=$indir; fi
    for infile in $(ls ${indir}/*.spt); do
        inname=$(basename $infile)
        echo $inname
        python ${SRC_DIR}/systemnnn_spt.py e $infile -o $outdir/$inname.txt
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
        7z e ${GAME_FILE%} */wajin_asaki.exe -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */init2/* -o${WORK_DIR}/1.origin/init2
        7z e ${GAME_FILE%} */nya/* -o${WORK_DIR}/1.origin/nya
        7z e ${GAME_FILE%} */spt/* -o${WORK_DIR}/1.origin/spt
    fi 

    if ! [ -d ${WORK_DIR}/2.pre ]; then
        echo "## init_workdir 2.pre"
        mkdir -p ${WORK_DIR}/2.pre
    fi

    if ! [ -d ${WORK_DIR}/3.edit ]; then
        echo "## init_workdir 3.edit"
        mkdir -p ${WORK_DIR}/3.edit
        mkdir -p ${WORK_DIR}/3.edit/init2_txt
        mkdir -p ${WORK_DIR}/3.edit/nya_txt
        mkdir -p ${WORK_DIR}/3.edit/spt_txt
        mkdir -p ${WORK_DIR}/3.edit/spt_ftext
        mkdir -p ${WORK_DIR}/3.edit/dwq_png # use garbro to extract
        
        # extract xtx
        cp -rp ${WORK_DIR}/1.origin/nya/*.xtx ${WORK_DIR}/3.edit/nya_txt
        find ${WORK_DIR}/3.edit/nya_txt -maxdepth 1 -type f -exec mv {} {}.txt \;
        cp -rp ${WORK_DIR}/1.origin/spt/*.xtx ${WORK_DIR}/3.edit/spt_txt
        find ${WORK_DIR}/3.edit/spt_txt -maxdepth 1 -type f -exec mv {} {}.txt \;
        
        # extract fxf
        decode_fxf ${WORK_DIR}/1.origin/init2 ${WORK_DIR}/3.edit/init2_txt
        decode_fxf ${WORK_DIR}/1.origin/spt ${WORK_DIR}/3.edit/spt_txt

        # extract spt
        extract_spt ${WORK_DIR}/1.origin/spt ${WORK_DIR}/3.edit/spt_ftext
    fi

    if ! [ -d ${WORK_DIR}/4.post ]; then
        echo "## init_workdir 4.post"
        mkdir -p ${WORK_DIR}/4.post
    fi

    if ! [ -d ${WORK_DIR}/5.result ]; then
        echo "## init_workdir 5.result"
        mkdir -p ${WORK_DIR}/5.result
        mkdir -p ${WORK_DIR}/5.result/override
        mkdir -p ${WORK_DIR}/5.result/override/dwq
        mkdir -p ${WORK_DIR}/5.result/override/init2
        mkdir -p ${WORK_DIR}/5.result/override/nya
        mkdir -p ${WORK_DIR}/5.result/override/png
        mkdir -p ${WORK_DIR}/5.result/override/spt
    fi
}

$* # to call function outside script