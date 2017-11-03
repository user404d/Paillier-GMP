#include <fstream>
#include <paillier.hpp>

int main()
{
    std::string c1 = "tmp/c1",
                m1 = "tmp/m1",
                c2 = "tmp/c2",
                m2 = "tmp/m2",
                m3 = "tmp/m3",
                priv_key = "tmp/priv4096",
                pub_key = "tmp/pub4096";

    {
        std::fstream plain_a(m1, plain_a.out);
        std::fstream plain_b(m2, plain_b.out);
        plain_a << 3 << std::endl;
        plain_b << 4 << std::endl;
    }

    paillier::io::keygen(pub_key, priv_key, 4096);
    paillier::io::encrypt(c1, m1, pub_key);
    paillier::io::mult_c(c2, c1, m2, pub_key);
    paillier::io::decrypt(m3, c2, priv_key);

    std::fstream result(m3, result.in);

    result >> m3;

    return m3 != "12";
}