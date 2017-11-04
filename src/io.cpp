#include <fstream>
#include "impl.hpp"
#include "io.hpp"

namespace paillier
{

namespace io
{

void add(ssv cipher_result_out, ssv cipher_a_in, ssv cipher_b_in, ssv pub_key_in)
{
    impl::key::Public pub{};
    impl::CipherText a{}, b{}, result{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream cipher_a(cipher_a_in.data(), cipher_a.in);
    std::fstream cipher_b(cipher_b_in.data(), cipher_b.in);
    std::fstream cipher_result(cipher_result_out.data(), cipher_result.out);

    pub_key >> pub;
    cipher_a >> a;
    cipher_b >> b;
    cipher_result << a.add(b, pub) << std::endl;
}

void decrypt(ssv plain_out, ssv cipher_in, ssv priv_key_in)
{
    impl::key::Private priv{};
    impl::CipherText c{};

    std::fstream priv_key(priv_key_in.data(), priv_key.in);
    std::fstream cipher(cipher_in.data(), cipher.in);
    std::fstream plain(plain_out.data(), plain.out);

    priv_key >> priv;
    cipher >> c;
    plain << c.decrypt(priv) << std::endl;
}

void encrypt(ssv cipher_out, ssv plain_in, ssv pub_key_in)
{
    impl::key::Public pub{};
    impl::PlainText p{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream plain(plain_in.data(), plain.in);
    std::fstream cipher(cipher_out.data(), cipher.out);

    pub_key >> pub;
    plain >> p;
    cipher << p.encrypt(pub) << std::endl;
}

void keygen(ssv pub_out, ssv priv_out, mp_bitcnt_t len)
{
    std::fstream pub(pub_out.data(), pub.out);
    std::fstream priv(priv_out.data(), priv.out);

    try
    {
        const auto & [ priv_key, pub_key ] = impl::key::gen(len);
        pub << pub_key;
        priv << priv_key;
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    catch (...)
    {
        std::cerr << "Error in key generation" << std::endl;
        exit(1);
    }
}

void keyseed(ssv pub_out, ssv priv_out, ssv seed_in)
{
    std::fstream seed(seed_in.data(), seed.in);
    std::fstream pub(pub_out.data(), pub.out);
    std::fstream priv(priv_out.data(), priv.out);

    mp_bitcnt_t k{};
    mpz_class p{}, q{}, g{};

    seed >> k >> p >> q >> g;

    if (p > q)
    {
        p.swap(q);
    }

    try
    {
        const auto & [ priv_key, pub_key ] = impl::key::seed(k, p, q, g);
        pub << pub_key;
        priv << priv_key;
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    catch (...)
    {
        std::cerr << "Error in key seeding" << std::endl;
        exit(1);
    }
}

void mult_c(ssv cipher_result_out, ssv cipher_in, ssv constant_in, ssv pub_key_in)
{
    impl::key::Public pub{};
    mpz_class cst{};
    impl::CipherText c{};

    std::fstream pub_key(pub_key_in.data(), pub_key.in);
    std::fstream constant(constant_in.data(), constant.in);
    std::fstream cipher(cipher_in.data(), cipher.in);
    std::fstream cipher_result(cipher_result_out.data(), cipher_result.out);

    pub_key >> pub;
    constant >> cst;
    cipher >> c;
    cipher_result << c.mult(cst, pub) << std::endl;
}

// io
}
// paillier
}
