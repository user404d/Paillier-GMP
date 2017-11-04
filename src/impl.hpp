#ifndef PAILLIER_IMPL_HPP
#define PAILLIER_IMPL_HPP

#include <iostream>
#include <gmpxx.h>

namespace paillier
{

namespace impl
{

namespace key
{

class Private
{
public:
  mp_bitcnt_t len;
  mpz_class lambda,
      mu,
      n,
      p2,
      p2invq2,
      q2;

  Private() = default;
  Private(
      mp_bitcnt_t len,
      mpz_class lambda,
      mpz_class mu,
      mpz_class n,
      mpz_class p2,
      mpz_class p2invq2,
      mpz_class q2) : len(len),
                      lambda(lambda),
                      mu(mu),
                      n(n),
                      p2(p2),
                      p2invq2(p2invq2),
                      q2(q2)
  {
  }

  friend std::istream &operator>>(std::istream &is, Private &priv);
  friend std::ostream &operator<<(std::ostream &os, const Private &priv);
};

class Public
{
public:
  mp_bitcnt_t len;
  mpz_class n;

  Public() = default;
  Public(
      mp_bitcnt_t len,
      mpz_class n) : len(len),
                     n(n)
  {
  }

  friend std::istream &operator>>(std::istream &is, Public &pub);
  friend std::ostream &operator<<(std::ostream &os, const Public &pub);
};

mpz_class ell(const mpz_class input, const mpz_class n);
std::pair<Private, Public> gen(const mp_bitcnt_t len);
mpz_class lambda(const mpz_class p, const mpz_class q);
mpz_class mu(const mpz_class n,
             const mpz_class g,
             const mpz_class lambda,
             const mpz_class p2,
             const mpz_class p2invq2,
             const mpz_class q2);
std::pair<Private, Public> seed(const mp_bitcnt_t k, const mpz_class p, const mpz_class q, const mpz_class g);

// key
}

class CipherText;
class PlainText;

class CipherText
{

public:
  mpz_class text;
  CipherText() = default;
  CipherText(mpz_class text) : text(text) {}
  CipherText add(CipherText a, key::Public pub) const;
  PlainText decrypt(key::Private priv) const;
  CipherText mult(mpz_class c, key::Public pub) const;

  friend std::istream &operator>>(std::istream &is, CipherText &cipher);
  friend std::ostream &operator<<(std::ostream &os, const CipherText &cipher);
};

class PlainText
{
public:
  mpz_class text;
  PlainText() = default;
  PlainText(mpz_class text) : text(text) {}
  CipherText encrypt(key::Public pub) const;

  friend std::istream &operator>>(std::istream &is, PlainText &plain);
  friend std::ostream &operator<<(std::ostream &os, const PlainText &plain);
};

//impl
}
// paillier
}

#endif // PAILLIER_IMPL_HPP
