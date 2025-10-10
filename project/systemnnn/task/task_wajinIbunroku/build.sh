build_1txt() {
    echo "## build_1txt"
    mkdir -p ${WORK_DIR}/5.result/override/init2
    mkdir -p ${WORK_DIR}/5.result/override/nya
    mkdir -p ${WORK_DIR}/5.result/override/spt

    echo "## build fxf"
    ./init.sh encode_fxf ${WORK_DIR}/3.edit/init2_txt ${WORK_DIR}/5.result/override/init2
    # ./init.sh encode_fxf ${WORK_DIR}/3.edit/spt_txt ${WORK_DIR}/5.result/override/spt

    echo "## build xtx"
    for infile in $(ls ${WORK_DIR}/3.edit/nya_txt/*.xtx.txt); do
        inname=$(basename $infile ".txt")
        echo $inname
        cp -f $infile ${WORK_DIR}/5.result/override/nya/$inname
    done
    for infile in $(ls ${WORK_DIR}/3.edit/spt_txt/*.xtx.txt); do
        inname=$(basename $infile)
        echo $inname
        cp -f $infile ${WORK_DIR}/5.result/override/spt/$inname
    done
}

build_1spt() {
    echo "## build_1spt"
    mkdir -p ${WORK_DIR}/5.result/override/spt

    for infile in $(ls ${WORK_DIR}/3.edit/spt_ftext/*.txt); do
        inname=$(basename $infile ".txt")
        echo $inname
       	python $SRC_DIR/systemnnn_spt.py i \
            ${WORK_DIR}/1.origin/spt/$inname -t $infile --encoding gbk \
            -o ${WORK_DIR}/5.result/override/spt/$inname 
    done
}

build_2dwq() {
    echo "## build_2dwq"
    mkdir -p ${WORK_DIR}/5.result/override/png

    if [ -f ${WORK_DIR}/3.edit/dwq_png/*.png ]; then
        cp -f ${WORK_DIR}/3.edit/dwq_png/*.png ${WORK_DIR}/5.result/override/png
    fi
}

build_3dll() {
    echo "## build_3dll"
    mkdir -p ${WORK_DIR}/5.result

    if [ -z "$CC" ]; then CC=$LLVMMINGW_HOME/bin/i686-w64-mingw32-clang; fi
    make -C ${SRC_DIR}/../ -f systemnnn.mk CC=$CC BUILD_DIR=${WORK_DIR}/4.post DEBUG=$DEBUG NOPDB=$NOPDB
    cp -f ${WORK_DIR}/4.post/systemnnn_patch.* ${WORK_DIR}/5.result
}

build_3exe() {
    echo "## build_3exe"
    mkdir -p ${WORK_DIR}/5.result/override

    python -B ${SRC_DIR}/compat/windllin_v0_3_2_1.py -m codecave2 \
        ${WORK_DIR}/1.origin/wajin_asaki.exe systemnnn_patch.dll \
        -o ${WORK_DIR}/5.result/wajin_asaki_chs.exe 1>/dev/null
    
    echo "## generate config file"
    echo "override_file=1" > ${WORK_DIR}/5.result/override/config.ini
    echo "override_font=1" >> ${WORK_DIR}/5.result/override/config.ini
    echo "createfontcharset=134" >> ${WORK_DIR}/5.result/override/config.ini
    echo "fontname=simhei" >> ${WORK_DIR}/5.result/override/config.ini
    echo "patch=+3DC17:FE" >> ${WORK_DIR}/5.result/override/config.ini
    echo "CPicture_LoadDWQ=939744" >> ${WORK_DIR}/5.result/override/config.ini
    echo "CPicture_mpic=32" >> ${WORK_DIR}/5.result/override/config.ini
    iconv -f utf-8 -t utf-16le -c ${WORK_DIR}/5.result/override/config.ini > ${WORK_DIR}/5.result/override/config2.ini
    mv -f ${WORK_DIR}/5.result/override/config2.ini ${WORK_DIR}/5.result/override/config.ini

    echo "## generate debug cmd"
    echo "wajin_asaki_chs.exe | tee wajin_asaki_chs_log.txt" > ${WORK_DIR}/5.result/wajin_asaki_chs_debug.cmd
}

release_patch() {
    echo "## release_patch"W
    RELEASE_NAME="[$(date +"%y%m%d")build][${GAME_ID}]${GAME_NAME}_${VERSION}[1CHSPATCH]"
    RELEASE_FILE=${WORK_DIR}/$RELEASE_NAME.7z
    RELEASE_DIR=${WORK_DIR}/5.result 
    echo $RELEASE_NAME
    7z a -mx5 $RELEASE_FILE $RELEASE_DIR
    7z rn $RELEASE_FILE $(basename $RELEASE_DIR) $RELEASE_NAME
}

$*