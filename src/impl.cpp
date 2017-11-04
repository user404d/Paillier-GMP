#include "impl.hpp"
#include <stdexcept>
#include "tools.hpp"

namespace paillier
{

namespace impl
{

namespace key
{

std::istream &operator>>(std::istream &is, Private &priv)
{
    is >> priv.len >> priv.lambda >> priv.mu >> priv.n >> priv.p2 >> priv.p2invq2 >> priv.q2;
    return is;
}

std::ostream &operator<<(std::ostream &os, const Private &priv)
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

std::istream &operator>>(std::istream &is, Public &pub)
{
    is >> pub.len >> pub.n;
    return is;
}

std::ostream &operator<<(std::ostream &os, const Public &pub)
{
    os << pub.len << "\n"
       << pub.n;
    return os;
}

mpz_class ell(const mpz_class input, const mpz_class n)
{
    return (input - 1U) / n;
}

std::pair<Private, Public> gen(const mp_bitcnt_t len)
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
    const mpz_class n{p * q};
    const mpz_class g{n + 1U};
    const mpz_class p2{p * p};
    const mpz_class q2{q * q};
    mpz_class p2invq2{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());
    const mpz_class lambda{key::lambda(p, q)};
    const mpz_class mu{key::mu(n, g, lambda, p2, p2invq2, q2)};
    return {{len, lambda, mu, n, p2, p2invq2, q2}, {len, n}};
}

mpz_class lambda(const mpz_class p, const mpz_class q)
{
    mpz_class p_1{p ^ 1U};
    mpz_class q_1{q ^ 1U};
    return {lcm(p_1, q_1)};
}

mpz_class mu(const mpz_class n,
             const mpz_class g,
             const mpz_class lambda,
             const mpz_class p2,
             const mpz_class p2invq2,
             const mpz_class q2)
{
    mpz_class result{};
    const mpz_class n2{n * n};
    mpz_class temp{tools::crt_exponentiation(g, lambda, lambda, p2invq2, p2, q2)};
    temp = ell(temp, n);
    if (!mpz_invert(result.get_mpz_t(), temp.get_mpz_t(), n.get_mpz_t()))
    {
        throw std::runtime_error("no inverse, mu, was found");
    }
    return result;
}

std::pair<Private, Public> seed(const mp_bitcnt_t k, const mpz_class p, const mpz_class q, const mpz_class g)
{
    if (p > q)
    {
        throw std::runtime_error("p should be less than q");
    }
    const mpz_class n{p * q};
    const mpz_class p2{p * p};
    const mpz_class q2{q * q};
    mpz_class p2invq2{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());
    const mpz_class lambda{key::lambda(p, q)};
    const mpz_class mu{key::mu(n, g, lambda, p2, p2invq2, q2)};
    return {{k, lambda, mu, n, p2, p2invq2, q2}, {k, n}};
}

// key
}

CipherText CipherText::add(CipherText a, key::Public pub) const
{
    return {(text * a.text) % (pub.n * pub.n)};
}

PlainText CipherText::decrypt(key::Private priv) const
{
    // std::cout << "~~~~~~~~~~~~ Decrypting ~~~~~~~~~~~" << std::endl
    //           << "text: " << text << std::endl
    //           << "lambda: " << priv.lambda << std::endl
    //           << "mu: " << priv.mu << std::endl
    //           << "n: " << priv.n << std::endl
    //           << "p2: " << priv.p2 << std::endl
    //           << "q2: " << priv.q2 << std::endl
    //           << "p2invq2: " << priv.p2invq2 << std::endl;
    mpz_class crt{tools::crt_exponentiation(text, priv.lambda, priv.lambda, priv.p2invq2, priv.p2, priv.q2)};
    // std::cout << "crt: " << crt << std::endl
    //           << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
    return {(key::ell(crt, priv.n) * priv.mu) % priv.n};
}

CipherText CipherText::mult(mpz_class constant, key::Public pub) const
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

CipherText PlainText::encrypt(key::Public pub) const
{
    // std::cout << "----------- Encrypting ------------" << std::endl
    //           << "plain: " << text << std::endl
    //           << "n: " << pub.n << std::endl;
    mpz_class result{};
    if (cmp(pub.n, text))
    {
        const mpz_class n2{pub.n * pub.n};
        mpz_class random{0U};
        // std::cout << "n^2: " << n2 << std::endl;
        while (random == 0U || gcd(random, pub.n) != 1)
        {
            random = tools::Random::get().random_n(pub.n);
        }
        // std::cout << "random: " << random << std::endl;
        mpz_powm(result.get_mpz_t(), random.get_mpz_t(), pub.n.get_mpz_t(), n2.get_mpz_t());
        const mpz_class temp{(text * pub.n) + 1U};
        result *= temp;
        result %= n2;
    }
    // std::cout << "result: " << result << std::endl
    //           << "------------------------------------" << std::endl;
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

// impl
}
// paillier
}
