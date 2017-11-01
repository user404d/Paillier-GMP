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
    auto exponentiate = [](mpz_class basis, mpz_class exponent, mpz_class modulus) {
        mpz_class result{};
        mpz_class basis_reduced = basis % modulus;
        mpz_powm(result.get_mpz_t(), basis_reduced.get_mpz_t(), exponent.get_mpz_t(), modulus.get_mpz_t());
        return result;
    };

    auto reduced_p = std::async(std::launch::async, exponentiate, base, exp_p, p);
    auto reduced_q = std::async(std::launch::async, exponentiate, base, exp_q, q);
    mpz_class pq = p * q;
    reduced_p.wait();
    mpz_class rp = reduced_p.get();
    reduced_q.wait();
    mpz_class rq = reduced_q.get();
    mpz_class result = rq - rp;
    result *= p;
    result *= pinvq;
    result += rp;
    result %= pq;

    return result;
}

mpz_class gen_prime(mp_bitcnt_t len)
{
    auto noise = std::random_device{};
    gmp_randclass gen(gmp_randinit_default);
    gen.seed(noise());
    mpz_class random = gen.get_z_bits(len);
    mpz_class prime{};

    mpz_setbit(random.get_mpz_t(), len - 1);
    mpz_nextprime(prime.get_mpz_t(), random.get_mpz_t());

    return prime;
}

mpz_class gen_pseudorandom(mp_bitcnt_t len)
{
    auto noise = std::random_device{};
    gmp_randclass gen(gmp_randinit_default);
    gen.seed(noise());
    return gen.get_z_bits(len);
}

// tools
}
// paillier
}