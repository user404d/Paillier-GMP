#include "impl.hpp"
#include <stdexcept>
#include "tools.hpp"

namespace paillier
{

namespace impl
{

CipherText CipherText::add(CipherText a, PublicKey pub) const
{
    return {(text * a.text) % (pub.n * pub.n)};
}

PlainText CipherText::decrypt(PrivateKey priv) const
{
    // std::cout << "~~~~~~~~~~~~Decrypt~~~~~~~~~~~" << std::endl
    //           << "text: " << text << std::endl
    //           << "lambda: " << priv.lambda << std::endl
    //           << "mu: " << priv.mu << std::endl
    //           << "n: " << priv.n << std::endl
    //           << "p2: " << priv.p2 << std::endl
    //           << "q2: " << priv.q2 << std::endl
    //           << "p2invq2: " << priv.p2invq2 << std::endl;
    mpz_class crt{tools::crt_exponentiation(text, priv.lambda, priv.lambda, priv.p2invq2, priv.p2, priv.q2)};
    // std::cout << "crt: " << crt << std::endl
    //           << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
    return {(ell(crt, priv.n) * priv.mu) % priv.n};
}

CipherText CipherText::mult(mpz_class constant, PublicKey pub) const
{
    mpz_class result{};
    mpz_class n2{pub.n * pub.n};
    mpz_powm(result.get_mpz_t(), text.get_mpz_t(), constant.get_mpz_t(), n2.get_mpz_t());
    return {std::move(result)};
}

std::istream &operator>>(std::istream &is, CipherText &cipher)
{
    is >> cipher.text;
    return is;
}

std::ostream &operator<<(std::ostream &os, const CipherText &cipher)
{
    os << cipher.text;
    return os;
}

CipherText PlainText::encrypt(PublicKey pub) const
{
    // std::cout << "----------- Encrypting ------------" << std::endl
    //           << "plain: " << text << std::endl
    //           << "n: " << pub.n << std::endl;
    mpz_class result{};
    if (cmp(pub.n, text))
    {
        mpz_class n2{pub.n * pub.n};
        mpz_class random{0U};
        // std::cout << "n^2: " << n2 << std::endl;
        while (random == 0U || gcd(random, pub.n) != 1)
        {
            random = tools::Random::get().random_n(pub.n);
        }
        // std::cout << "random: " << random << std::endl;
        mpz_powm(result.get_mpz_t(), random.get_mpz_t(), pub.n.get_mpz_t(), n2.get_mpz_t());
        mpz_class temp{(text * pub.n) + 1U};
        result *= temp;
        result %= n2;
    }
    // std::cout << "result: " << result << std::endl
    //           << "-------------------------------------" << std::endl;
    return {std::move(result)};
}

std::istream &operator>>(std::istream &is, PlainText &plain)
{
    is >> plain.text;
    return is;
}

std::ostream &operator<<(std::ostream &os, const PlainText &plain)
{
    os << plain.text;
    return os;
}

std::istream &operator>>(std::istream &is, PrivateKey &priv)
{
    is >> priv.len >> priv.lambda >> priv.mu >> priv.n >> priv.p2 >> priv.p2invq2 >> priv.q2;
    return is;
}

std::ostream &operator<<(std::ostream &os, const PrivateKey &priv)
{
    os << priv.len << "\n"
       << priv.lambda << "\n"
       << priv.mu << "\n"
       << priv.n << "\n"
       << priv.p2 << "\n"
       << priv.p2invq2 << "\n"
       << priv.q2;
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
       << pub.n;
    return os;
}

KeyPair keygen(mp_bitcnt_t len)
{
    mpz_class p{tools::Random::get().prime(len / 2)};
    mpz_class q{tools::Random::get().prime(len / 2)};
    while (p == q)
    {
        q = tools::Random::get().prime(len / 2);
    }
    if (p > q)
    {
        p.swap(q);
    }
    mpz_class n{p * q};
    mpz_class g{n + 1U};
    mpz_class p2{p * p};
    mpz_class q2{q * q};
    mpz_class p2invq2{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());
    mpz_class p_1{p ^ 1U};
    mpz_class q_1{q ^ 1U};
    mpz_class lambda{lcm(p_1, q_1)};
    mpz_class n2{n * n};
    mpz_class temp{tools::crt_exponentiation(g, lambda, lambda, p2invq2, p2, q2)};
    temp = ell(temp, n);
    mpz_class mu{};
    if (!mpz_invert(mu.get_mpz_t(), temp.get_mpz_t(), n.get_mpz_t()))
    {
        throw std::runtime_error("no inverse mu was found");
    }
    return {{len, lambda, mu, n, p2, p2invq2, q2}, {len, n}};
}

mpz_class ell(mpz_class input, mpz_class n)
{
    return (input - 1U) / n;
}

//impl
}
// paillier
}