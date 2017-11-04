# Secure Dot Product

## Authors

Akshatha Bhat | Quincy Conduff | Sai Sruti

## Description

Secure dot product protocol using Paillier homomorphic encryption. Paillier homomorphic encryption was implemented using GMP.

## Requirements

- C++ 17 compliant compiler
- make `>=3.81`
- cmake `>=3.2`
- gmp `>= 6.1.2`
  - Requires both `gmp.h` and `gmpxx.h` for C++ compatibility

## Installation

```sh
git clone https://github.com/user404d/Paillier-GMP.git
cd Paillier-GMP
make
```

## Usage

```sh
$ ./bin/secure_dot_product --help
Secure dot product using Paillier homomorphic encryption
Usage:
  secure_dot_product [OPTION...]

      --help        Print help message
      --seed arg    Seed key generation with k,p,q,g
      --keygen arg  Generate keys using k bits
      --pub arg     File for public key
      --priv arg    File for private key
  -u, arg           File for vector u input
      --eu arg      File for encrypted vector u output
  -v, arg           File for vector v input
      --ev arg      File for encrypted vector v output
      --result arg  File for dot product output
```

### Usage Notes

- Using `--seed arg` has precedence over `--keygen arg`.
- The size of `k` for key generation should be at least `2*s` where `s` is the number of bits needed to represent the dot product. This will allow the computation to be performed safely.
- If public and private keys are already known or generated, then simply remove the `--keygen arg` flag and provide the path to each file.

### Seed File Format

```plain
<k bits>
<p>
<q>
<g>
```

#### Seed Example

File `seed.in`.

```plain
8
7
11
78
```

### Key File Format

All values are integers separated by whitespace (newlines by default).

#### Public Key

```plain
<k bits>
<n>
```

##### Public Key Example

File `pub.key`.

```plain
8
143
```

#### Private Key

```plain
<k bits>
<lambda>
<mu>
<n>
<p^2>
<(p^2)^-1 mod (q^2)>
<q^2>
```

##### Private Key Example

File `priv.key`.

```plain
8
60
31
143
121
88
169
```

### Vector File Format

A vector file contains white space delimited positive integers.

`<int><space|tab|newline><int><space|tab|newline>...<int>`

#### Examples

File `u.vec`.

```plain
0 1 2 3 4 5
```

File `v.vec`.

```plain
5
4
3
2
1
0
```

## Demo Usage

Taken from `test/functional_test.sh`.

```sh
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
```
