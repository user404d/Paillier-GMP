#include <future>
#include <iostream>
#include <random>
#include "tools.hpp"

namespace paillier
{

namespace tools
{

inline void debug_msg(std::string_view msg)
{
#ifdef PAILLIER_DEBUG
    std::cerr << msg.c_str() << "\n";
#endif
}

mpz_class crt_exponentiation(const mpz_class base,
                             const mpz_class exp_p,
                             const mpz_class exp_q,
                             const mpz_class pinvq,
                             const mpz_class p,
                             const mpz_class q)
{
    static const auto exponentiate = [](const mpz_class basis, const mpz_class exponent, const mpz_class modulus) {
        mpz_class result{};
        mpz_class basis_reduced{basis % modulus};
        mpz_powm(result.get_mpz_t(), basis_reduced.get_mpz_t(), exponent.get_mpz_t(), modulus.get_mpz_t());
        return result;
    };

    std::future<mpz_class> reduced_p = std::async(std::launch::async, exponentiate, base, exp_p, p);
    std::future<mpz_class> reduced_q = std::async(std::launch::async, exponentiate, base, exp_q, q);
    const mpz_class pq{p * q};
    reduced_p.wait();
    reduced_q.wait();
    const mpz_class rp{reduced_p.get()};
    const mpz_class rq{reduced_q.get()};
    mpz_class result{(rq - rp + q) * pinvq};
    result = rp + (result % q) * p;
    result %= pq;

    return result;
}

mpz_class Random::prime(const mp_bitcnt_t len)
{
    const mpz_class random{gen.get_z_bits(len)};
    mpz_class prime{};
    mpz_nextprime(prime.get_mpz_t(), random.get_mpz_t());
    while (!mpz_probab_prime_p(prime.get_mpz_t(), 15))
    {
        mpz_nextprime(prime.get_mpz_t(), prime.get_mpz_t());
    }
    return prime;
}

mpz_class Random::random_n(const mpz_class n)
{
    return gen.get_z_range(n);
}

// tools
}
// paillier
}
