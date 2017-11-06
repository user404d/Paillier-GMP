#!/bin/bash -e

TMP=tmp
U_VEC=u.vec
V_VEC=v.vec
RESULT=u_dot_v.out

test_result()
{
    if [ "$1" -eq "$2" ]; then
        echo "[+] -> $1 == $2"
    else
        echo "[-] -> $1 != $2"
        if [ `head -n 2 $3 | tail -1` -le $2 ]; then
            echo "output was larger than modulo n found in $3"
        fi
    fi
}

test -d ${TMP} || mkdir tmp
echo "1 3 5 2 3 1 4" > ${TMP}/${U_VEC}
echo "2 2 2 2 2 2 2" > ${TMP}/${V_VEC}

./../bin/secure_dot_product --keygen 4096 \
    --pub ${TMP}/pub.key \
    --priv ${TMP}/priv.key \
    -u  ${TMP}/${U_VEC} \
    -v ${TMP}/${V_VEC} \
    --eu ${TMP}/u.vec.enc \
    --ev ${TMP}/v.vec.enc \
    --result ${TMP}/${RESULT}

test_result `tail -1 ${TMP}/${RESULT}` "38" ${TMP}/pub.key