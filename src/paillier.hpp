#ifndef PAILLIER_HPP
#define PAILLIER_HPP

#include <iostream>
#include <gmpxx.h>

namespace paillier
{

namespace impl
{

class CipherText;
struct KeyPair;
class PlainText;
class PrivateKey;
class PublicKey;

class CipherText
{
public:
  mpz_class text;
  CipherText() = default;
  CipherText(mpz_class text) : text(text) {}
  CipherText add(CipherText a, PublicKey pub);
  PlainText decrypt(PrivateKey priv);
  CipherText mult(mpz_class c, PublicKey pub);

  friend std::istream &operator>>(std::istream &is, CipherText &cipher);
  friend std::ostream &operator<<(std::ostream &os, const CipherText &cipher);
};

class PlainText
{
public:
  mpz_class text;
  PlainText() = default;
  PlainText(mpz_class text) : text(text) {}
  CipherText encrypt(PublicKey pub);

  friend std::istream &operator>>(std::istream &is, PlainText &plain);
  friend std::ostream &operator<<(std::ostream &os, const PlainText &plain);
};

class PrivateKey
{
public:
  mp_bitcnt_t len;
  mpz_class lambda,
      mu,
      n,
      ninv,
      p2,
      p2invq2,
      q2;

  PrivateKey() = default;
  PrivateKey(
      mp_bitcnt_t len,
      mpz_class lambda,
      mpz_class mu,
      mpz_class n,
      mpz_class ninv,
      mpz_class p2,
      mpz_class p2invq2,
      mpz_class q2) : len(len),
                      lambda(lambda),
                      mu(mu),
                      n(n),
                      ninv(ninv),
                      p2(p2),
                      p2invq2(p2invq2),
                      q2(q2)
  {
  }

  friend std::istream &operator>>(std::istream &is, PrivateKey &priv);
  friend std::ostream &operator<<(std::ostream &os, const PrivateKey &priv);
};

class PublicKey
{
public:
  mp_bitcnt_t len;
  mpz_class n;

  PublicKey() = default;
  PublicKey(
      mp_bitcnt_t len,
      mpz_class n) : len(len),
                     n(n)
  {
  }

  friend std::istream &operator>>(std::istream &is, PublicKey &pub);
  friend std::ostream &operator<<(std::ostream &os, const PublicKey &pub);
};

struct KeyPair
{
  PrivateKey priv;
  PublicKey pub;
};

KeyPair keygen(mp_bitcnt_t len);
mpz_class ell(mpz_class input, mpz_class ninv, mp_bitcnt_t len);

//impl
}
// paillier
}

#endif