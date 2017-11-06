#include <future>
#include <iostream>
#include <random>
#include "tools.hpp"

namespace paillier::tools
{

inline void debug_msg(std::string_view msg)
{
#ifdef PAILLIER_DEBUG
    std::cerr << msg.c_str() << "\n";
#endif
}

/*
 * The exponentiation is computed using Garner's method for the CRT:
 * 
 * Exponentiation mod p: y_p = (x mod p)^{exp_p} mod p
 * Exponentiation mod q: y_q = (x mod q)^{exp_q} mod q
 * Recombination: y = y_p + p*(p^{-1} mod q)*(y_q-y_p) mod n
 * 
 * NOTE: p MUST be greater than q
 * 
 * The exponentiations mod p and mod q may run in their own thread.
 */
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

    const mpz_class pq{p * q}, rp{reduced_p.get()}, rq{reduced_q.get()};

    mpz_class result{(rq - rp + q) * pinvq};
    result = rp + (result % q) * p;
    result %= pq;

    return result;
}

/*
 * Generate probable prime of given bit length.
 */
mpz_class Random::prime(const mp_bitcnt_t len)
{
    mpz_class random{gen.get_z_bits(len)}, prime{};
    // ensures that the prime generated has the right number of bits
    mpz_setbit(random.get_mpz_t(), len - 1);
    mpz_nextprime(prime.get_mpz_t(), random.get_mpz_t());
    while (!mpz_probab_prime_p(prime.get_mpz_t(), 15))
    {
        mpz_nextprime(prime.get_mpz_t(), prime.get_mpz_t());
    }
    return prime;
}

/*
 * Generate random number from 0 to n exclusive.
 */
mpz_class Random::random_n(const mpz_class n)
{
    return gen.get_z_range(n);
}

} // paillier::tools
