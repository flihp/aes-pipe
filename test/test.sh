#!/bin/sh

AES_PIPE=../src/aes-pipe
DIR_TMP=$(mktemp --directory --tmpdir=/tmp aptmp.XXXXXX)
KEY_PREFIX=${DIR_TMP}/key

DATA_PT_PREFIX=${DIR_TMP}/data_pt
DATA_EVEN_PT=${DIR_TMP}/data_even.pt
DATA_ODD_PT=${DIR_TMP}/data_odd.pt

KEY_SIZES="128 192 256"
TEST_SIZES="1 4096 4097"
LOG=${DIR_TMP}/test.log

echo "generating test data: ${DATA_EVEN_PT}" >> ${LOG}
for SIZE in ${TEST_SIZES}; do
    DATA_PT_FILE=${DATA_PT_PREFIX}.${SIZE}
    dd if=/dev/urandom of=${DATA_PT_FILE} bs=${SIZE} count=1 >> ${LOG} 2>&1
    if [ $? -ne 0 ]; then
        exit 1
    fi
done

for SIZE in ${KEY_SIZES}; do
    KEY_FILE=${KEY_PREFIX}.${SIZE}

    echo "generating keyfile: ${KEY_FILE}" >> ${LOG}
    dd if=/dev/urandom of=${KEY_FILE} bs=$((${SIZE}/8)) count=1 >> ${LOG} 2>&1
    if [ $? -ne 0 ]; then
        exit 1
    fi

    for TEST_SIZE in ${TEST_SIZES}; do
        TEST_FILE=${DATA_PT_PREFIX}.${TEST_SIZE}
        TEST_FILE_DEC=${TEST_FILE}.dec.${SIZE}
        TEST_FILE_ENC=${TEST_FILE}.enc.${SIZE}
        
        echo "+++++++++++++++++++++++++++++++++++++++++++++" >> ${LOG}
        echo "encrypting data file ${TEST_FILE} with key ${KEY_FILE}" >> ${LOG}
        cat ${TEST_FILE} | ${AES_PIPE} --verbose --encrypt --keyfile ${KEY_FILE} > ${TEST_FILE_ENC} 2>> ${LOG}
        if [ $? -ne 0 ]; then
            echo "failed to encrypt ${TEST_FILE} with key ${KEY_FILE} to ${TEST_FILE_ENC}" >> ${LOG}
        fi
        echo "+++++++++++++++++++++++++++++++++++++++++++++" >> ${LOG}
        echo "decrypting data file ${TEST_FILE} with key ${KEY_FILE}" >> ${LOG}
        cat ${TEST_FILE_ENC} | ${AES_PIPE} --verbose --decrypt --keyfile ${KEY_FILE} > ${TEST_FILE_DEC} 2>> ${LOG}
        if [ $? -ne 0 ]; then
            echo "failed to decrypt ${TEST_FILE_ENC} with key ${KEY_FILE} to ${TEST_FILE_DEC}" >> ${LOG}
        fi
        
        echo "comparing file ${TEST_FILE} to file ${TEST_FILE_DEC}"  >> ${LOG}
        cmp ${TEST_FILE} ${TEST_FILE_DEC}
        case $? in
            0)  echo "success" >> ${LOG}
                ;;
            1)  echo "Test failed:"
                echo "   Files ${TEST_FILE} and ${TEST_FILE_DEC} differ."
                echo "   Preserving test data."
                ;;
            2)  echo "cmp command returned an error: test failed"
                ;;
        esac
    done
done
