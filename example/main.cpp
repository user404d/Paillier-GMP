#include "cxxopts.hpp"
#include <cinttypes>
#include <fstream>
#include <iostream>
#include <paillier.hpp>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    cxxopts::Options options("secure_dot_product", "Secure dot product using Paillier homomorphic encryption");

    std::uint64_t k = 0ULL;
    std::string eu, ev, priv, pub, result, seed, u, v;

    options.add_options()                                              //
        ("h, help", "Print help message")                              //
        ("pk", "Public key (required)", cxxopts::value(pub), "FILE")   //
        ("sk", "Private key (required)", cxxopts::value(priv), "FILE") //
        ;
    options.add_options("key generation")                                          //
        ("seed", "Seed key generation with k,p,q,g", cxxopts::value(seed), "FILE") //
        ("k, kbits", "Generate keys using k bits", cxxopts::value(k), "uint64")    //
        ;
    options.add_options("input")                                             //
        ("u", "Vector u", cxxopts::value(u)->default_value("u.vec"), "FILE") //
        ("v", "Vector v", cxxopts::value(v)->default_value("v.vec"), "FILE") //
        ;
    options.add_options("output")                                                                        //
        ("eu", "Encrypted vector u", cxxopts::value(eu)->default_value("u.vec.enc"), "FILE")             //
        ("ev", "Encrypted vector v", cxxopts::value(ev)->default_value("v.vec.enc"), "FILE")             //
        ("o,output", "Dot product of u and v", cxxopts::value(result)->default_value("res.out"), "FILE") //
        ;

    if (argc <= 1)
    {
        std::cout << options.help({"", "key generation", "input", "output"}) << std::endl;
        exit(0);
    }

    try
    {
        options.parse(argc, argv);

        if (options.count("help"))
        {
            std::cout << options.help({"", "key generation", "input", "output"}) << std::endl;
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
    if (options.count("pk") && options.count("sk"))
    {
        if (options.count("seed"))
        {
            io::keyseed(pub, priv, seed);
        }
        else if (options.count("kbits"))
        {
            if (k <= 0)
            {
                std::cerr << "k must be a positive integer greater than 0" << std::endl;
                exit(1);
            }
            io::keygen(pub, priv, k);
        }
    }
    else
    {
        std::cerr << "both the private and public keys must have filepaths provided" << std::endl;
        exit(1);
    }

    impl::key::Public pub_key{};
    impl::key::Private priv_key{};

    {
        std::fstream pub_in(pub, pub_in.in);
        std::fstream priv_in(priv, priv_in.in);
        pub_in >> pub_key;
        priv_in >> priv_key;
    }

    const auto u_vec = sdp::read_vector<impl::PlainText>(u);
    const auto v_vec = sdp::read_vector<impl::PlainText>(v);

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
    else if (u_vec.size() == 0)
    {
        std::cerr << "vectors should not have dimension size of 0" << std::endl;
        exit(1);
    }

    const auto encrypt = [=](const impl::PlainText &p) { return p.encrypt(pub_key); };

    const auto eu_vec = sdp::map<impl::PlainText, impl::CipherText>(u_vec, encrypt);
    const auto ev_vec = sdp::map<impl::PlainText, impl::CipherText>(v_vec, encrypt);

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

    const auto mult = [=](const impl::CipherText &c, const impl::PlainText &p) {
        return c.mult(p.text, pub_key);
    };

    const auto ev_u_vec = sdp::pairwise_map<impl::CipherText, impl::PlainText, impl::CipherText>(ev_vec, u_vec, mult);

    const auto add = [=](const impl::CipherText &acc, const impl::CipherText &c) {
        return acc.add(c, pub_key);
    };

    const auto e_dot_prod = sdp::reduce<impl::CipherText, impl::CipherText>(ev_u_vec, add, impl::PlainText(0).encrypt(pub_key));
    const auto dot_prod = e_dot_prod.decrypt(priv_key);

    // std::cout << "dot_prod: " << dot_prod << std::endl;

    {
        std::fstream res(result, res.out);
        res << e_dot_prod << "\n"
            << dot_prod << std::endl;
    }

    return 0;
}
