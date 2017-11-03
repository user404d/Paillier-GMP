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

mpz_class crt_exponentiation(mpz_class base,
                             mpz_class exp_p,
                             mpz_class exp_q,
                             mpz_class pinvq,
                             mpz_class p,
                             mpz_class q);

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
    static Random &get()
    {
        static Random instance;
        return instance;
    }

    mpz_class prime(mp_bitcnt_t len);
    mpz_class random_n(mpz_class n);
};

// tools
}
// paillier
}

#endif // TOOLS_HPP