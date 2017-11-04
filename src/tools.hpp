#ifndef PAILLIER_TOOLS_HPP
#define PAILLIER_TOOLS_HPP

#include <gmpxx.h>
#include <memory>
#include <random>
#include <string>

namespace paillier
{

namespace tools
{

inline void debug_msg(std::string_view msg);

mpz_class crt_exponentiation(const mpz_class base,
                             const mpz_class exp_p,
                             const mpz_class exp_q,
                             const mpz_class pinvq,
                             const mpz_class p,
                             const mpz_class q);

class Random
{
    std::random_device noise;
    gmp_randclass gen;

  protected:
    Random() : gen(gmp_randinit_default)
    {
        gen.seed(noise());
    }

  public:
    Random(Random const &) = delete;
    Random(Random &&) = delete;

    static Random &get()
    {
        static Random instance;
        return instance;
    }

    mpz_class prime(const mp_bitcnt_t len);
    mpz_class random_n(const mpz_class n);
};

// tools
}
// paillier
}

#endif // PAILLIER_TOOLS_HPP
