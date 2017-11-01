#include <fstream>
#include <iostream>
#include "io.hpp"

int main()
{
    using namespace paillier::io;

    std::string c1 = "c1",
                m1 = "m1",
                c2 = "c2",
                m2 = "m2",
                c3 = "c3",
                m3 = "m3",
                m4 = "m4",
                c5 = "c5",
                m5 = "m5",
                priv_key = "priv4096",
                pub_key = "pub4096";

    {
        std::fstream plain_a(m1, plain_a.out);
        std::fstream plain_b(m2, plain_b.out);
        std::fstream plain_c(m4, plain_c.out);
        plain_a << 3 << std::endl;
        plain_b << 4 << std::endl;
        plain_c << 5 << std::endl;
    }

    keygen(pub_key, priv_key, 4096);
    encrypt(c1, m1, pub_key);
    encrypt(c2, m2, pub_key);
    add(c3, c1, c2, pub_key);
    decrypt(m3, c3, priv_key);

    mult_c(c5, c2, m4, pub_key);
    decrypt(m5, c5, priv_key);

    std::fstream result_add(m3, result_add.in);
    std::fstream result_mul(m5, result_mul.in);
    result_add >> m3;
    result_mul >> m5;
    std::cout << m3 << std::endl
              << std::endl
              << m5 << std::endl;

    return 0;
}
