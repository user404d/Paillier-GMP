#include <fstream>
#include "io.hpp"
#include "paillier.hpp"

namespace paillier
{

namespace io
{

void add(ssv cipher_result_out, ssv cipher_a_in, ssv cipher_b_in, ssv pub_key_in)
{
    impl::PublicKey pub{};
    impl::CipherText a{}, b{}, result{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream cipher_a(cipher_a_in.data(), cipher_a.in);
    std::fstream cipher_b(cipher_b_in.data(), cipher_b.in);
    std::fstream cipher_result(cipher_result_out.data(), cipher_result.out);

    pub_key >> pub;
    cipher_a >> a;
    cipher_b >> b;
    result.text = a.text * b.text;
    cipher_result << result;
}

void decrypt(ssv plain_out, ssv cipher_in, ssv priv_key_in)
{
    impl::PrivateKey priv{};
    impl::CipherText c{};
    impl::PlainText p{};

    std::fstream priv_key(priv_key_in.data(), priv_key.in);
    std::fstream cipher(cipher_in.data(), cipher.in);
    std::fstream plain(plain_out.data(), plain.out);

    priv_key >> priv;
    cipher >> c;
    p = c.decrypt(priv);
    plain << p;
}

void encrypt(ssv cipher_out, ssv plain_in, ssv pub_key_in)
{
    impl::PublicKey pub{};
    impl::PlainText p{};
    impl::CipherText c{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream plain(plain_in.data(), plain.in);
    std::fstream cipher(cipher_out.data(), cipher.out);

    pub_key >> pub;
    plain >> p;
    c = p.encrypt(pub);
    cipher << c;
}

void keygen(ssv pub_out, ssv priv_out, mp_bitcnt_t len)
{
    std::fstream pub(pub_out.data(), pub.out);
    std::fstream priv(priv_out.data(), priv.out);

    try
    {
        const auto & [ priv_key, pub_key ] = impl::keygen(len);
        pub << pub_key;
        priv << priv_key;
    }
    catch (const std::runtime_error e)
    {
        std::cerr << e.what() << "\n";
        exit(1);
    }
    catch (...)
    {
        std::cerr << "oops\n";
        exit(1);
    }
}

void mult_c(ssv cipher_result_out, ssv cipher_in, ssv constant_in, ssv pub_key_in)
{
    impl::PublicKey pub{};
    mpz_class cst{};
    impl::CipherText c{}, result{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream constant(constant_in.data(), constant.in);
    std::fstream cipher(cipher_in.data(), cipher.in);
    std::fstream cipher_result(cipher_result_out.data(), cipher_result.out);

    pub_key >> pub;
    constant >> cst;
    cipher >> c;
    result = c.mult(cst, pub);
    cipher_result << result;
}

// io
}
// paillier
}