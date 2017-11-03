#!/bin/bash -e

TMP=tmp
U_VEC=u.vec
V_VEC=v.vec
RESULT=u_dot_v.out

test -d ${TMP} || mkdir tmp
echo "1 2 3" > ${TMP}/${U_VEC}
echo "3 2 1" > ${TMP}/${V_VEC}

./../bin/secure_dot_product --keygen \
    -k 4096 \
    --pub ${TMP}/pub.key \
    --priv ${TMP}/priv.key \
    -u  ${TMP}/${U_VEC} \
    -v ${TMP}/${V_VEC} \
    --eu ${TMP}/u.vec.enc \
    --ev ${TMP}/v.vec.enc \
    --result ${TMP}/${RESULT}

cat ${TMP}/${RESULT}