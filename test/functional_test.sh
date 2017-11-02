#!/bin/bash -e

TMP=tmp
U_VEC=u.vec
V_VEC=v.vec

test -d ${TMP} || mkdir tmp
echo "3 4 5" > ${TMP}/${U_VEC}
echo "1 2 3" > ${TMP}/${V_VEC}

./../bin/secure_dot_product -k 4096 \
    --pub ${TMP}/pub.key \
    --priv ${TMP}/priv.key \
    -u  ${TMP}/${U_VEC} \
    -v ${TMP}/${V_VEC} \
    --eu ${TMP}/u.vec.enc \
    --ev ${TMP}/v.vec.enc \
    --result ${TMP}/u_dot_v.out