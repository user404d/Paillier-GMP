#ifndef PAILLIER_TOOLS_HPP
#define PAILLIER_TOOLS_HPP

#include <future>
#include <gmpxx.h>
#include <iostream>
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
mpz_class gen_prime(mp_bitcnt_t len);
mpz_class gen_pseudorandom(mp_bitcnt_t len);

// tools
}
// paillier
}

#endif // TOOLS_HPP