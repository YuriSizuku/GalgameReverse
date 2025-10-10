build_1mjo() {
    echo "## build_1mjo"
    mkdir -p ${WORK_DIR}/4.post/data_mjil
    mkdir -p ${WORK_DIR}/4.post/data_mjov

    echo "## ftext -> mjil"
    for inpath in $(ls ${WORK_DIR}/3.edit/data_ftext/*.txt); do
        inname=$(basename $inpath ".mjil.txt") # xxx.mjil
        echo $inname.mjil.txt
        python -B ${SRC_DIR}/majiro_mjiltext.py icp936 $inpath \
            ${WORK_DIR}/2.pre/data_mjil/$inname.mjil \
            ${WORK_DIR}/4.post/data_mjil/$inname.mjil
    done

    echo "## mjil adjust"
    if [ -f ${WORK_DIR}/3.edit/sorairo_adjust.py ]; then
        python -B ${WORK_DIR}/3.edit/sorairo_adjust.py ${WORK_DIR}/4.post/data_mjil 
    fi

    echo "## mjil -> mjo, from data_ftext"
    for inpath in $(ls ${WORK_DIR}/3.edit/data_ftext/*.txt); do
        inname=$(basename $inpath ".mjil.txt") # xxx.mjil
        echo $inname.mjil
        cd ${TOOL_DIR}
        python -B -m mjotool2 -G sorairo \
            -a ${WORK_DIR}/4.post/data_mjil/$inname.mjil \
            ${WORK_DIR}/4.post/data_mjov/$inname.mjo \
            --text-encoding cp936
        cd -
    done

    echo "## mjil-> mjo from data_mjil"
    for inpath in $(ls ${WORK_DIR}/3.edit/data_mjil/*.mjil); do
        inname=$(basename $inpath ".mjil") # xxx.mjil
        echo $inname.mjil
        cd ${TOOL_DIR}
        python -B -m mjotool2 -G sorairo \
            -a ${WORK_DIR}/3.edit/data_mjil/$inname.mjil \
            ${WORK_DIR}/4.post/data_mjov/$inname.mjo \
            --text-encoding cp936
        cd -
    done
}

build_2arc() {
    echo "## build_2arc"
    mkdir -p ${WORK_DIR}/4.post/update
    mkdir -p ${WORK_DIR}/4.post/data_mjov
    mkdir -p ${WORK_DIR}/5.result/override
    cp -f ${WORK_DIR}/4.post/data_mjov/*.mjo ${WORK_DIR}/4.post/update/
    cp -f ${WORK_DIR}/3.edit/data_cfg/* ${WORK_DIR}/4.post/update/
    cp -f ${WORK_DIR}/3.edit/data_png/*.png ${WORK_DIR}/4.post/update/
    cp -f ${WORK_DIR}/1.origin/update2.arc ${WORK_DIR}/5.result/update5.arc
    python ${SRC_DIR}/majiro_arc.py b \
        ${WORK_DIR}/4.post/update \
        ${WORK_DIR}/5.result/override/update5.arc
}

build_3dll() {
    echo "## build_3dll"
    mkdir -p ${WORK_DIR}/4.post
    mkdir -p ${WORK_DIR}/5.result
    if [ -z "$CC" ]; then CC=$LLVMMINGW_HOME/bin/i686-w64-mingw32-clang; fi
    make -C ${SRC_DIR}/../ -f majiro.mk CC=$CC BUILD_DIR=${WORK_DIR}/4.post DEBUG=$DEBUG
    cp -f ${WORK_DIR}/4.post/majiro_patch.*  ${WORK_DIR}/5.result
}

build_3exe() {
    echo "## build_3exe"
    mkdir -p ${WORK_DIR}/4.post
    mkdir -p ${WORK_DIR}/5.result
    cp -f ${WORK_DIR}/1.origin/そらいろ_v1.1.exe ${WORK_DIR}/4.post/_sorairo_chs.exe

    if [ -f ${WORK_DIR}/3.edit/sorairo_sjis.txt ]; then
        echo "## import sorairo_sjis.txt"
        python -B ${SRC_DIR}/compat/libtext_v0_6_3.py insert \
            ${WORK_DIR}/4.post/_sorairo_chs.exe \
            ${WORK_DIR}/3.edit/sorairo_sjis.txt \
            -o ${WORK_DIR}/4.post/_sorairo_chs.exe \
            -e "gbk"  --bytes_padding 00 --text_replace 〜 ~ \
            --log_level error
    fi

    if [ -f ${WORK_DIR}/3.edit/sorairo_utf16.txt ]; then
        echo "## import sorairo_utf16.txt"
        python -B ${SRC_DIR}/compat/libtext_v0_6_3.py insert \
            ${WORK_DIR}/4.post/_sorairo_chs.exe \
            ${WORK_DIR}/3.edit/sorairo_utf16.txt \
            -o ${WORK_DIR}/4.post/_sorairo_chs.exe \
            -e "utf-16le"  --bytes_padding 2000 \
            --log_level error
    fi

    echo "## inject majiro_patch.dll to sorairo"
    python -B ${SRC_DIR}/compat/windllin_v0_3_2_1.py -m codecave2 \
        ${WORK_DIR}/4.post/_sorairo_chs.exe  majiro_patch.dll \
        -o ${WORK_DIR}/5.result/sorairo_chs.exe 1>/dev/null
    
    echo "## generate config file"
    echo "override_file=1" > ${WORK_DIR}/5.result/override/config.ini
    echo "override_codepage=1" >> ${WORK_DIR}/5.result/override/config.ini
    echo "codepage=936" >> ${WORK_DIR}/5.result/override/config.ini
    echo "override_font=1" >> ${WORK_DIR}/5.result/override/config.ini
    echo "createfontcharset=134" >> ${WORK_DIR}/5.result/override/config.ini
    echo "enumfontcharset=128" >> ${WORK_DIR}/5.result/override/config.ini
    echo "patch=+38C0:C3;+1903B:B8A1;+19087:B8A1;+19A7A:B8A1;+1905D:B9A1;+19AF0:B9A1" >> ${WORK_DIR}/5.result/override/config.ini
    # echo "usegbk=1" >> ${WORK_DIR}/5.result/override/config.ini
    iconv -f utf-8 -t utf-16le -c ${WORK_DIR}/5.result/override/config.ini > ${WORK_DIR}/5.result/override/config2.ini
    mv -f ${WORK_DIR}/5.result/override/config2.ini ${WORK_DIR}/5.result/override/config.ini

    echo "## generate debug cmd"
    echo "sorairo_chs.exe | tee sorairo_chs_log.txt" > ${WORK_DIR}/5.result/sorairo_chs_debug.cmd
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