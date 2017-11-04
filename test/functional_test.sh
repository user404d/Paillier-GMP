#!/bin/bash -e

TMP=tmp
U_VEC=u.vec
V_VEC=v.vec
RESULT=u_dot_v.out

test -d ${TMP} || mkdir tmp
echo "1 3 5 2 3 1 4" > ${TMP}/${U_VEC}
echo "2 2 2 2 2 2 2" > ${TMP}/${V_VEC}

./../bin/secure_dot_product --keygen 8 \
    --pub ${TMP}/pub.key \
    --priv ${TMP}/priv.key \
    -u  ${TMP}/${U_VEC} \
    -v ${TMP}/${V_VEC} \
    --eu ${TMP}/u.vec.enc \
    --ev ${TMP}/v.vec.enc \
    --result ${TMP}/${RESULT}

tail -1 ${TMP}/${RESULT}