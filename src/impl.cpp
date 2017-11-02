#include "impl.hpp"
#include <stdexcept>
#include "tools.hpp"

namespace paillier
{

namespace impl
{

CipherText CipherText::add(CipherText a, PublicKey pub)
{
    mpz_class n2 = pub.n * pub.n;
    return {mpz_class(text * a.text) % n2};
}

PlainText CipherText::decrypt(PrivateKey priv)
{
    mpz_class p_text = tools::crt_exponentiation(text, priv.lambda, priv.lambda, priv.p2invq2, priv.p2, priv.q2);
    p_text = ell(p_text, priv.ninv, priv.len);
    p_text *= priv.mu;
    p_text %= priv.n;
    return {p_text};
}

CipherText CipherText::mult(mpz_class constant, PublicKey pub)
{
    mpz_class result{};
    mpz_class n2 = pub.n * pub.n;
    mpz_powm(result.get_mpz_t(), text.get_mpz_t(), constant.get_mpz_t(), n2.get_mpz_t());
    return {result};
}

std::istream &operator>>(std::istream &is, CipherText &cipher)
{
    is >> cipher.text;
    return is;
}

std::ostream &operator<<(std::ostream &os, const CipherText &cipher)
{
    os << cipher.text << "\n";
    return os;
}

CipherText PlainText::encrypt(PublicKey pub) const
{
    mpz_class result{};
    if (mpz_cmp(pub.n.get_mpz_t(), text.get_mpz_t()))
    {
        mpz_class n2 = pub.n * pub.n;
        mpz_class random = tools::gen_pseudorandom(pub.len);
        random %= pub.n;
        if (mpz_cmp_ui(random.get_mpz_t(), 0) == 0)
        {
            throw std::runtime_error("random number was zero");
        }
        mpz_powm(result.get_mpz_t(), random.get_mpz_t(), pub.n.get_mpz_t(), n2.get_mpz_t());
        random = text * pub.n;
        random += 1;
        result *= random;
        result %= n2;
    }
    return {result};
}

std::istream &operator>>(std::istream &is, PlainText &plain)
{
    is >> plain.text;
    return is;
}

std::ostream &operator<<(std::ostream &os, const PlainText &plain)
{
    os << plain.text << "\n";
    return os;
}

std::istream &operator>>(std::istream &is, PrivateKey &priv)
{
    is >> priv.len >> priv.lambda >> priv.mu >> priv.n >> priv.ninv >> priv.p2 >> priv.p2invq2 >> priv.q2;
    return is;
}

std::ostream &operator<<(std::ostream &os, const PrivateKey &priv)
{
    os << priv.len << "\n"
       << priv.lambda << "\n"
       << priv.mu << "\n"
       << priv.n << "\n"
       << priv.ninv << "\n"
       << priv.p2 << "\n"
       << priv.p2invq2 << "\n"
       << priv.q2 << "\n";
    return os;
}

std::istream &operator>>(std::istream &is, PublicKey &pub)
{
    is >> pub.len >> pub.n;
    return is;
}

std::ostream &operator<<(std::ostream &os, const PublicKey &pub)
{
    os << pub.len << "\n"
       << pub.n << "\n";
    return os;
}

KeyPair keygen(mp_bitcnt_t len)
{
    mpz_class p = tools::gen_prime(len / 2);
    mpz_class q = tools::gen_prime(len / 2);
    mpz_class n = p * q;
    mpz_class g = n + 1;
    mpz_class ninv{}, temp{};
    mpz_setbit(temp.get_mpz_t(), len);
    if (!mpz_invert(ninv.get_mpz_t(), n.get_mpz_t(), temp.get_mpz_t()))
    {
        throw std::runtime_error("no inverse for p and q");
    }
    mpz_class p2 = p * p;
    mpz_class q2 = q * q;
    mpz_class p2invq2{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());
    mpz_class p_1 = p - 1;
    mpz_class q_1 = q - 1;
    mpz_class lambda{};
    mpz_lcm(lambda.get_mpz_t(), p_1.get_mpz_t(), q_1.get_mpz_t());
    mpz_class n2 = n * n;
    temp = tools::crt_exponentiation(g, lambda, lambda, p2invq2, p2, q2);
    temp = ell(temp, ninv, len);
    mpz_class mu{};
    if (!mpz_invert(mu.get_mpz_t(), temp.get_mpz_t(), n.get_mpz_t()))
    {
        throw std::runtime_error("no inverse mu was found");
    }
    return KeyPair{{len, lambda, mu, n, ninv, p2, p2invq2, q2}, {len, n}};
}

mpz_class ell(mpz_class input, mpz_class ninv, mp_bitcnt_t len)
{
    mpz_class mask{};
    mpz_class result = input - 1;
    result *= ninv;
    mpz_setbit(mask.get_mpz_t(), len);
    mpz_sub_ui(mask.get_mpz_t(), mask.get_mpz_t(), 1);
    result &= mask;
    return result;
}

//impl
}
// paillier
}