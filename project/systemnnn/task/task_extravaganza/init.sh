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

init_mingwsdk() {
    echo "## init_mingwsdk ${MINGWSDK}"
    if ! [ -d ${MINGWSDK} ]; then
        if [ -n "$(uname -a | grep Linux)" ]; then
            curl -fsSL https://github.com/mstorsjo/llvm-mingw/releases/download/20240619/llvm-mingw-20240619-msvcrt-ubuntu-20.04-x86_64.tar.xz -o /tmp/llvm-mingw.tar.xz
            tar xf /tmp/llvm-mingw.tar.xz -C /tmp
            _tmppath=/tmp/llvm-mingw-20240619-msvcrt-ubuntu-20.04-x86_64 
            mv -f ${_tmppath} $MINGWSDK || echo "try to use sudo mv to $MINGWSDK" && sudo mv -f ${_tmppath} $MINGWSDK
            rm -rf /tmp/llvm-mingw.tar.xz
        else
            curl -fsSL https://github.com/mstorsjo/llvm-mingw/releases/download/20240619/llvm-mingw-20240619-msvcrt-x86_64.zip -o ~/llvm-mingw.zip
            7z x ~/llvm-mingw.zip -o$HOME
            mv -f ~/llvm-mingw-20240619-msvcrt-x86_64 $MINGWSDK
            rm -rf ~/llvm-mingw.zip
        fi
    fi
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
        7z e ${GAME_FILE%} */mushiai.exe -o${WORK_DIR}/1.origin
        7z e ${GAME_FILE%} */init/* -o${WORK_DIR}/1.origin/init
        7z e ${GAME_FILE%} */chart/* -o${WORK_DIR}/1.origin/chart
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
        mkdir -p ${WORK_DIR}/3.edit/nya
        mkdir -p ${WORK_DIR}/3.edit/spt
        mkdir -p ${WORK_DIR}/3.edit/chart_text
        mkdir -p ${WORK_DIR}/3.edit/init_text
        mkdir -p ${WORK_DIR}/3.edit/spt_text
        mkdir -p ${WORK_DIR}/3.edit/spt_ftext
        mkdir -p ${WORK_DIR}/3.edit/dwq_png # use garbro to extract
        
        # extract xtx
        cp -rp ${WORK_DIR}/1.origin/nya/*.xtx ${WORK_DIR}/3.edit/nya
        cp -rp ${WORK_DIR}/1.origin/spt/*.xtx ${WORK_DIR}/3.edit/spt
        
        # extract fxf
        decode_fxf ${WORK_DIR}/1.origin/init ${WORK_DIR}/3.edit/init_text
        decode_fxf ${WORK_DIR}/1.origin/chart ${WORK_DIR}/3.edit/chart_text
        decode_fxf ${WORK_DIR}/1.origin/spt ${WORK_DIR}/3.edit/spt_text

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
        mkdir -p ${WORK_DIR}/5.result/override/init
        mkdir -p ${WORK_DIR}/5.result/override/chart
        mkdir -p ${WORK_DIR}/5.result/override/nya
        mkdir -p ${WORK_DIR}/5.result/override/png
        mkdir -p ${WORK_DIR}/5.result/override/spt
    fi
}

$* # to call function outside script