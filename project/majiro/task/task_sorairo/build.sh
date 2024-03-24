build_1mjo() {
    echo "## build_1mjo"

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
    if [ -n "$(uname -a | grep Linux)" ]; then
        if [ -z "$CC" ]; then CC=i686-w64-mingw32-gcc; fi
    else
        if [ -z "$CC" ]; then CC=clang; fi
    fi
    make -C ${SRC_DIR}/../ -f majiro.mk CC=$CC BUILD_DIR=${WORK_DIR}/5.result DEBUG=1
}

build_3exe() {
    echo "## build_3exe"
    cp -f ${WORK_DIR}/1.origin/そらいろ_v1.1.exe ${WORK_DIR}/4.post/_sorairo_chs.exe

    if [ -f ${WORK_DIR}/3.edit/sorairo_sjis.txt ]; then
        echo "## import sorairo_sjis.txt"
        python -B ${SRC_DIR}/compat/libtext_v610.py insert \
            ${WORK_DIR}/4.post/_sorairo_chs.exe \
            ${WORK_DIR}/3.edit/sorairo_sjis.txt \
            -o ${WORK_DIR}/4.post/_sorairo_chs.exe \
            -e "gbk"  --bytes_padding 00 --text_replace 〜 ~ \
            --log_level error
    fi

    if [ -f ${WORK_DIR}/3.edit/sorairo_utf16.txt ]; then
        echo "## import sorairo_utf16.txt"
        python -B ${SRC_DIR}/compat/libtext_v610.py insert \
            ${WORK_DIR}/4.post/_sorairo_chs.exe \
            ${WORK_DIR}/3.edit/sorairo_utf16.txt \
            -o ${WORK_DIR}/4.post/_sorairo_chs.exe \
            -e "utf-16le"  --bytes_padding 2000 \
            --log_level error
    fi

    echo "## inject majiro_patch.dll to sorairo"
    python -B ${SRC_DIR}/compat/windllin_v321.py -m codecave2 \
        ${WORK_DIR}/4.post/_sorairo_chs.exe  majiro_patch.dll \
        -o ${WORK_DIR}/5.result/sorairo_chs.exe 1>/dev/null
    
    echo "## generate config file"
    echo "charset=134" > ${WORK_DIR}/5.result/override/config.ini
    echo "codepage=936" >> ${WORK_DIR}/5.result/override/config.ini
    echo "patch=+38C0:C3;+1903B:B8A1;+19087:B8A1;+19A7A:B8A1;+1905D:B9A1;+19AF0:B9A1" >> ${WORK_DIR}/5.result/override/config.ini
}

release_patch() {
    echo "## release_patch"W
    RELEASE_NAME="[$(date +"%y%m%d")build][vndb-v1914]Sorairo_${VERSION}[1CHSPATCH]"
    RELEASE_FILE=${WORK_DIR}/$RELEASE_NAME.7z
    RELEASE_DIR=${WORK_DIR}/5.result 
    echo $RELEASE_NAME
    7z a -mx5 $RELEASE_FILE $RELEASE_DIR
    7z rn $RELEASE_FILE $(basename $RELEASE_DIR) $RELEASE_NAME
}

$*