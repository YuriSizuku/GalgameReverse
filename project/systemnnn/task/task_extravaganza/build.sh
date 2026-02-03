build_1txt() {
    echo "## build_1init"
    mkdir -p ${WORK_DIR}/5.result/override/chart
    mkdir -p ${WORK_DIR}/5.result/override/init
    mkdir -p ${WORK_DIR}/5.result/override/nya
    mkdir -p ${WORK_DIR}/5.result/override/spt

    echo "## build fxf"
    ./init.sh encode_fxf ${WORK_DIR}/3.edit/chart_text ${WORK_DIR}/5.result/override/chart
    ./init.sh encode_fxf ${WORK_DIR}/3.edit/spt_text ${WORK_DIR}/5.result/override/spt

    echo "## build xtx"
    cp -rp ${WORK_DIR}/3.edit/nya/*.xtx ${WORK_DIR}/5.result/override/nya
    cp -rp ${WORK_DIR}/3.edit/init/*.xtx ${WORK_DIR}/5.result/override/init
    cp -rp ${WORK_DIR}/3.edit/spt/*.xtx ${WORK_DIR}/5.result/override/spt
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

    cp -f ${WORK_DIR}/3.edit/dwq_png/*.png ${WORK_DIR}/5.result/override/png
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

    echo "## inject dll in exe"
    mkdir -p ${WORK_DIR}/5.result/override
    python -B ${SRC_DIR}/compat/windllin_v0_3_2_1.py -m codecave2 \
        ${WORK_DIR}/1.origin/mushiai.exe systemnnn_patch.dll \
        -o ${WORK_DIR}/5.result/mushiai_chs.exe 1>/dev/null 2>/dev/null
    
    echo "## patch exe with translation"
    if [ -f "${WORK_DIR}/3.edit/mushiai.txt" ]; then
    python -B ${SRC_DIR}/compat/libtext_v0_6_3.py insert \
        -e gbk --bytes_fallback "81f2" --log_level error \
        ${WORK_DIR}/5.result/mushiai_chs.exe \
        "${WORK_DIR}/3.edit/mushiai.txt" \
        -o ${WORK_DIR}/5.result/mushiai_chs.exe
    fi
    
    echo "## generate config file"
    echo "override_file=1" > ${WORK_DIR}/5.result/override/config.ini
    echo "override_font=1" >> ${WORK_DIR}/5.result/override/config.ini
    echo "createfontcharset=134" >> ${WORK_DIR}/5.result/override/config.ini
    echo "fontname=simhei" >> ${WORK_DIR}/5.result/override/config.ini
    echo "patch=+1A547:FE;+201CB:0D" >> ${WORK_DIR}/5.result/override/config.ini
    echo "CPicture_LoadDWQ=56928" >> ${WORK_DIR}/5.result/override/config.ini
    echo "CPicture_mpic=32" >> ${WORK_DIR}/5.result/override/config.ini
    echo "CPicture_mmaskPic=40" >> ${WORK_DIR}/5.result/override/config.ini
    iconv -f utf-8 -t utf-16le -c ${WORK_DIR}/5.result/override/config.ini > ${WORK_DIR}/5.result/override/config2.ini
    mv -f ${WORK_DIR}/5.result/override/config2.ini ${WORK_DIR}/5.result/override/config.ini

    echo "## generate debug cmd"
    echo "mushiai_chs.exe | tee mushiai_chs_log.txt" > ${WORK_DIR}/5.result/mushiai_chs_debug.cmd
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

if [ -f "_env.sh" ]; then source _env.sh; fi
$*