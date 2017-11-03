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

mpz_class crt_exponentiation(mpz_class base,
                             mpz_class exp_p,
                             mpz_class exp_q,
                             mpz_class pinvq,
                             mpz_class p,
                             mpz_class q)
{
    static auto exponentiate = [](mpz_class basis, mpz_class exponent, mpz_class modulus) {
        mpz_class result{};
        mpz_class basis_reduced{basis % modulus};
        mpz_powm(result.get_mpz_t(), basis_reduced.get_mpz_t(), exponent.get_mpz_t(), modulus.get_mpz_t());
        return result;
    };

    std::future<mpz_class> reduced_p = std::async(std::launch::async, exponentiate, base, exp_p, p);
    std::future<mpz_class> reduced_q = std::async(std::launch::async, exponentiate, base, exp_q, q);
    mpz_class pq{p * q};
    reduced_p.wait();
    reduced_q.wait();
    mpz_class rp{reduced_p.get()};
    mpz_class rq{reduced_q.get()};
    mpz_class result{(rq - rp + q) * pinvq};
    result = rp + (result % q) * p;
    result %= pq;

    return result;
}

mpz_class Random::prime(mp_bitcnt_t len)
{
    mpz_class random{gen.get_z_bits(len)};
    mpz_class prime{};
    mpz_nextprime(prime.get_mpz_t(), random.get_mpz_t());
    while (!mpz_probab_prime_p(prime.get_mpz_t(), 15))
    {
        mpz_nextprime(prime.get_mpz_t(), prime.get_mpz_t());
    }
    return prime;
}

mpz_class Random::random_n(mpz_class n)
{
    return gen.get_z_range(n);
}

// tools
}
// paillier
}