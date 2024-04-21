build_1ws2() {
    echo "## build_1ws2"
    rios=$(find ${WORK_DIR}/1.origin -type f -name Rio*.arc -exec basename -s .arc {} \;|sort)
    for rio in $rios; do
        cp -rf ${WORK_DIR}/2.pre/$rio/* ${WORK_DIR}/4.post/$rio
        if [ -d ${WORK_DIR}/3.edit/${rio}_ftext ]; then
            echo ${rio}_ftext
            for infile in $(ls ${WORK_DIR}/3.edit/${rio}_ftext/*.txt); do
                inname=$(basename $infile .txt)
                echo ${rio}/$inname # .ws2
                python -B ${SRC_DIR}/advhd_ws2.py icp936 $infile \
                    ${WORK_DIR}/2.pre/${rio}/$inname \
                    ${WORK_DIR}/4.post/${rio}/$inname
            done
        fi

        if [ -d ${WORK_DIR}/3.edit/${rio}_ftext2 ]; then
            echo ${rio}_ftext2
            for infile in $(ls ${WORK_DIR}/3.edit/${rio}_ftext2/*.txt); do
                inname=$(basename $infile .txt)
                echo ${rio}/$inname # .ws2
                python -B ${SRC_DIR}/compat/libtext_v620.py insert \
                    ${WORK_DIR}/2.pre/${rio}/$inname $infile \
                    -o ${WORK_DIR}/4.post/${rio}/$inname -e gbk --bytes_padding 20
            done
        fi
    done
}

build_1lua() {
    echo "## build_1lua"
    cp -rf ${WORK_DIR}/2.pre/Script/* ${WORK_DIR}/4.post/Script
    for infile in $(ls ${WORK_DIR}/3.edit/Script_ftext/*.txt); do
        inname=$(basename $infile .txt)
        echo $inname
        python -B ${SRC_DIR}/compat/libtext_v620.py insert \
            ${WORK_DIR}/2.pre/Script/$inname $infile \
            -o ${WORK_DIR}/4.post/Script/$inname -e gbk --bytes_padding 20
    done
}

build_2pna() {
    echo "## build_2pna"
    cp -rf ${WORK_DIR}/2.pre/SysGraphic/* ${WORK_DIR}/4.post/SysGraphic # for build arc
    for inname in $(ls ${WORK_DIR}/3.edit/SysGraphic_png); do
        echo $inname 
        python -B ${SRC_DIR}/advhd_pna.py i \
            ${WORK_DIR}/3.edit/SysGraphic_png/$inname \
            ${WORK_DIR}/2.pre/SysGraphic/$inname.pna \
            ${WORK_DIR}/4.post/SysGraphic/$inname.pna
    done 
}

build_3arcv2() {
    echo "## build_3arcv2"
    arcs=$(find ${WORK_DIR}/1.origin -type f -name *.arc -exec basename -s .arc {} \;|sort)
    for arc in $arcs; do
        echo $arc
        python -B ${SRC_DIR}/advhd_arcv2.py b \
            ${WORK_DIR}/4.post/$arc \
            ${WORK_DIR}/5.result/override/$arc.arc
    done
}

build_4dll() {
    echo "## build_4dll"
    if [ -n "$(uname -a | grep Linux)" ]; then
        if [ -z "$CC" ]; then CC=i686-w64-mingw32-gcc; fi
    else
        if [ -z "$CC" ]; then CC=clang; fi
    fi
    make -C ${SRC_DIR}/../ -f advhd.mk CC=$CC BUILD_DIR=${WORK_DIR}/5.result DEBUG=1
}

build_4exe() {
    echo "## build_4exe"
    python -B ${SRC_DIR}/compat/windllin_v321.py -m codecave2 \
        ${WORK_DIR}/1.origin/AdvHD.exe advhd_patch.dll \
        -o ${WORK_DIR}/5.result/AdvHD_chs.exe 1>/dev/null

    echo "codepage=936" > ${WORK_DIR}/5.result/override/config.ini
    echo "charset=134" >> ${WORK_DIR}/5.result/override/config.ini
    echo "font=simhei" >> ${WORK_DIR}/5.result/override/config.ini
}

release_patch() {
    echo "## release_patch"W
    RELEASE_NAME="[$(date +"%y%m%d")build][vndb-v17853]BlackishHouse_${VERSION}[1CHSPATCH]"
    RELEASE_FILE=${WORK_DIR}/$RELEASE_NAME.7z
    RELEASE_DIR=${WORK_DIR}/5.result 
    echo $RELEASE_NAME
    7z a -mx5 $RELEASE_FILE $RELEASE_DIR
    7z rn $RELEASE_FILE $(basename $RELEASE_DIR) $RELEASE_NAME
}

$*