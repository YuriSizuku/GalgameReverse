# sh -c "VERSION=v0.8.1 ./release_patch.sh"
GAME_ID=PCSG00768
GAME_NAME=WalpurgisNoUta_psv
CHSPATCH_DIR=/d/Make/reverse/WalpurgisNoUta_psv/workflow
CHSPATCH_NAME=5.result
CHSPATCH_PATH=$CHSPATCH_DIR/$CHSPATCH_NAME

RELEASE_DIR=/d/Make/reverse/WalpurgisNoUta_psv/workflow
RELEASE_NAME=[$(date +"%y%m%d")build][${GAME_ID}]${GAME_NAME}_$VERSION[1CHSPATCH]
RELEASE_PATH=$RELEASE_DIR/$RELEASE_NAME

pushd $CHSPATCH_DIR
7z a -mx9 ${RELEASE_NAME}.7z ${CHSPATCH_NAME}
7z rn  ${RELEASE_NAME}.7z ${CHSPATCH_NAME} ${RELEASE_NAME}/${GAME_ID}
popd 