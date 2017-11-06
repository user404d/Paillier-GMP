#ifndef PAILLIER_IO_HPP
#define PAILLIER_IO_HPP

#include <gmpxx.h>
#include <string>

namespace paillier::io
{

using ssv = std::string_view;

void add(ssv cipher_result_out, ssv cipher_a_in, ssv cipher_b_in, ssv pub_key_in);
void decrypt(ssv plain_out, ssv cipher_in, ssv priv_key_in);
void encrypt(ssv cipher_out, ssv plain_in, ssv pub_key_in);
void keygen(ssv pub_out, ssv priv_out, mp_bitcnt_t len);
void keyseed(ssv pub_out, ssv priv_out, ssv seed_in);
void mult_c(ssv cipher_result_out, ssv cipher_in, ssv constant_in, ssv pub_key_in);

} // paillier::io

#endif // PAILLIER_IO_HPP
