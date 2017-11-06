#include <future>
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
    is >> priv.k >> priv.lambda >> priv.mu >> priv.n >> priv.p2 >> priv.p2invq2 >> priv.q2;
    return is;
}

std::ostream &operator<<(std::ostream &os, const Private &priv)
{
    os << priv.k << "\n"
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
    is >> pub.k >> pub.n >> pub.g;
    return is;
}

std::ostream &operator<<(std::ostream &os, const Public &pub)
{
    os << pub.k << "\n"
       << pub.n << "\n"
       << pub.g;
    return os;
}

/*
 * Performs integer division on (input - 1) by n.
 * 
 * L(x) = floor((x - 1) / n)
 * 
 * https://en.wikipedia.org/wiki/Paillier_cryptosystem#Background
 */
mpz_class ell(const mpz_class input, const mpz_class n)
{
    return (input - 1U) / n;
}

/*
 * Generates Private and Public keys using specified bit width.
 * 
 * Public (n,g=n+1)
 * Private (lambda, mu)
 * 
 * https://en.wikipedia.org/wiki/Paillier_cryptosystem#Key_generation
 */
std::pair<Private, Public> gen(const mp_bitcnt_t k)
{
    // find two probable primes p and q
    mpz_class p{tools::Random::get().prime(k / 2)};
    mpz_class q{tools::Random::get().prime(k / 2)};

    // p needs to be relatively prime to q
    while (p == q)
    {
        q = tools::Random::get().prime(k / 2);
    }

    // p should be less than q for CRT exponentiation
    if (p > q)
    {
        p.swap(q);
    }

    return key::seed(k, p, q);
}

/*
 * Find parameter lambda for given primes p and q.
 * 
 * lambda = lcm(p - 1, q - 1)
 * 
 * lcm: least common multiple
 */
mpz_class lambda(const mpz_class p, const mpz_class q)
{
    mpz_class p_1{p ^ 1U};
    mpz_class q_1{q ^ 1U};

    return {lcm(p_1, q_1)};
}

/*
 * Find parameter mu given n, g, lambda, p^2, (p^2)^-1 mod (q^2), and q^2.
 * 
 * mu = L(g^lambda mod (n^2))^-1 mod n
 * 
 * L: ell
 */
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

std::pair<Private, Public> seed(const mp_bitcnt_t k, const mpz_class p, const mpz_class q)
{
    if (p > q)
    {
        throw std::runtime_error("p should be less than q");
    }

    // compute n = p * q, g = n + 1, p^2, q^2
    const mpz_class n{p * q},
        g{n + 1U},
        p2{p * p},
        q2{q * q},
        lambda{key::lambda(p, q)};

    // precompute (p^2)^-1 mod (q^2) to speed up CRT exponentiation
    mpz_class p2invq2{}, mu{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());
    if (!mpz_invert(mu.get_mpz_t(), lambda.get_mpz_t(), n.get_mpz_t()))
    {
        throw std::runtime_error("no inverse, mu, was found");
    }

    return {{k, lambda, mu, n, p2, p2invq2, q2}, {k, n, 0U}};
}

/*
 * Seed public and private key generation with parameters k, p, q, and g.
 * Similar to normal generation, but primes p and q are provided.
 */
std::pair<Private, Public> seed(const mp_bitcnt_t k, const mpz_class p, const mpz_class q, const mpz_class g)
{
    if (p > q)
    {
        throw std::runtime_error("p should be less than q");
    }

    const mpz_class n{p * q}, p2{p * p}, q2{q * q}, lambda{key::lambda(p, q)};

    if (gcd(g, n) != 1)
    {
        throw std::runtime_error("g is not relatively prime to n");
    }

    mpz_class p2invq2{};
    mpz_invert(p2invq2.get_mpz_t(), p2.get_mpz_t(), q2.get_mpz_t());

    const mpz_class mu{key::mu(n, g, lambda, p2, p2invq2, q2)};

    return {{k, lambda, mu, n, p2, p2invq2, q2}, {k, n, g}};
}

// key
}

/*
 * "Add" two plaintexts homomorphically by multiplying ciphertexts modulo n^2.
 * For example, given the ciphertexts c1 and c2, encryptions of plaintexts m1 and m2,
 * the value c3=c1*c2 mod n^2 is a ciphertext that decrypts to m1+m2 mod n.
 */
CipherText CipherText::add(CipherText a, key::Public pub) const
{
    return {(text * a.text) % (pub.n * pub.n)};
}

/*
 * The decryption function computes m = L(c^lambda mod n^2)*mu mod n.
 * The exponentiation is calculated using the CRT, and exponentiations mod p^2 and q^2 run in their own thread.
 */
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

/*
 * "Multiplies" a plaintext with a constant homomorphically by exponentiating the ciphertext modulo n^2 with the constant as exponent.
 * For example, given the ciphertext c, encryptions of plaintext m, and the constant 5,
 * the value c3=c^5 n^2 is a ciphertext that decrypts to 5*m mod n.
 */
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

/*
 * The function calculates c=g^m*r^n mod n^2 with r random number.
 * Encryption benefits from the fact that g=1+n, because (1+n)^m = 1+n*m mod n^2.
 */
CipherText PlainText::encrypt(key::Public pub) const
{
    static const auto exponentiate = [](const mpz_class basis, const mpz_class exp, const mpz_class modulus) {
        mpz_class result{};
        mpz_powm(result.get_mpz_t(), basis.get_mpz_t(), exp.get_mpz_t(), modulus.get_mpz_t());
        return result;
    };
    // std::cout << "----------- Encrypting ------------" << std::endl
    //           << "plain: " << text << std::endl
    //           << "n: " << pub.n << std::endl;
    mpz_class result{};

    if (pub.n != text)
    {
        const mpz_class n2{pub.n * pub.n};
        mpz_class random{0U}, temp{};
        // std::cout << "n^2: " << n2 << std::endl;
        /* 
         * Encryption and decryption do not work properly for g = 1+n*m when the
         * random number chosen is a multiple of primes p or q
         *
         * https://crypto.stackexchange.com/questions/18058/choosing-primes-in-the-paillier-cryptosystem
         */
        while (random == 0U || gcd(random, pub.n) != 1)
        {
            random = tools::Random::get().random_n(pub.n);
        }
        // std::cout << "random: " << random << std::endl;

        std::future<mpz_class> f_result = std::async(std::launch::async, exponentiate, random, pub.n, n2);

        if (pub.g == 0U)
        {
            temp = (text * pub.n) + 1U;
        }
        else
        {
            std::future<mpz_class> f_temp = std::async(std::launch::async, exponentiate, pub.g, text, n2);
            temp = f_temp.get();
        }

        result = f_result.get();
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
