#include "cxxopts.hpp"
#include <fstream>
#include <iostream>
#include <paillier.hpp>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    cxxopts::Options options("secure_dot_product", "Secure dot product using Paillier homomorphic encryption");

    int k = 0;
    std::string eu, ev, priv, pub, result, seed, u, v;

    options.add_options()                                                               //
        ("help", "Print help message")                                                  //
        ("seed", "Seed key generation with k,p,q,g", cxxopts::value<std::string>(seed)) //
        ("keygen", "Generate keys using k bits", cxxopts::value<int>(k))                //
        ("pub", "File for public key", cxxopts::value<std::string>(pub))                //
        ("priv", "File for private key", cxxopts::value<std::string>(priv))             //
        ("u", "File for vector u input", cxxopts::value<std::string>(u))                //
        ("eu", "File for encrypted vector u output", cxxopts::value<std::string>(eu))   //
        ("v", "File for vector v input", cxxopts::value<std::string>(v))                //
        ("ev", "File for encrypted vector v output", cxxopts::value<std::string>(ev))   //
        ("result", "File for dot product output", cxxopts::value<std::string>(result))  //
        ;

    try
    {
        options.parse(argc, argv);

        if (options.count("help"))
        {
            std::cout << options.help({""}) << std::endl;
            exit(0);
        }
    }
    catch (const cxxopts::OptionException &e)
    {
        std::cerr << "error parsing options: " << e.what() << std::endl;
        exit(1);
    }

    using namespace paillier;

    // std::cout << "k: " << k << std::endl;

    if (options.count("seed"))
    {
        io::keyseed(pub, priv, seed);
    }
    else if (options.count("keygen"))
    {
        if (k <= 0)
        {
            std::cerr << "k must be a positive integer greater than 0" << std::endl;
            exit(1);
        }
        io::keygen(pub, priv, k);
    }

    impl::key::Public pub_key{};
    impl::key::Private priv_key{};

    {
        std::fstream pub_in(pub, pub_in.in);
        std::fstream priv_in(priv, priv_in.in);
        pub_in >> pub_key;
        priv_in >> priv_key;
    }

    auto u_vec = sdp::read_vector<impl::PlainText>(u);
    auto v_vec = sdp::read_vector<impl::PlainText>(v);

    // std::cout << "u: [\n";
    // for (const auto &u_i : u_vec)
    // {
    //     std::cout << u_i << std::endl;
    // }
    // std::cout << "]" << std::endl;

    // std::cout << "v: [\n";
    // for (const auto &v_i : v_vec)
    // {
    //     std::cout << v_i << std::endl;
    // }
    // std::cout << "]" << std::endl;

    if (u_vec.size() != v_vec.size())
    {
        std::cerr << "vectors u and v are not the same length" << std::endl;
        exit(1);
    }

    auto encrypt = [=](const impl::PlainText &p) { return p.encrypt(pub_key); };

    auto eu_vec = sdp::map<impl::PlainText, impl::CipherText>(u_vec, encrypt);
    auto ev_vec = sdp::map<impl::PlainText, impl::CipherText>(v_vec, encrypt);

    // std::cout << "u (decrypted): [\n";
    // for (const auto &eu_i : eu_vec)
    // {
    //     auto u_i = eu_i.decrypt(priv_key);
    //     std::cout << u_i << "," << std::endl;
    // }
    // std::cout << "]" << std::endl;

    // std::cout << "v (decrypted): [\n";
    // for (const auto &ev_i : ev_vec)
    // {
    //     auto v_i = ev_i.decrypt(priv_key);
    //     std::cout << v_i << "," << std::endl;
    // }
    // std::cout << "]" << std::endl;

    sdp::write_vector<impl::CipherText>(eu, eu_vec);
    sdp::write_vector<impl::CipherText>(ev, ev_vec);

    auto mult = [=](const impl::CipherText &c, const impl::PlainText &p) {
        return c.mult(p.text, pub_key);
    };

    auto ev_u_vec = sdp::pairwise_map<impl::CipherText, impl::PlainText, impl::CipherText>(ev_vec, u_vec, mult);

    auto add = [=](const impl::CipherText &acc, const impl::CipherText &c) {
        return acc.add(c, pub_key);
    };

    auto e_dot_prod = sdp::reduce<impl::CipherText, impl::CipherText>(ev_u_vec, add, impl::PlainText(0).encrypt(pub_key));
    auto dot_prod = e_dot_prod.decrypt(priv_key);

    // std::cout << "dot_prod: " << dot_prod << std::endl;

    {
        std::fstream res(result, res.out);
        res << e_dot_prod << "\n"
            << dot_prod << std::endl;
    }

    return 0;
}
