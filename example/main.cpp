#include "cxxopts.hpp"
#include <fstream>
#include <iostream>
#include <paillier.hpp>
#include <string>
#include <vector>

int main(int argc, char **argv)
{
    cxxopts::Options options("Secure Dot Product", "Secure dot product using Paillier homomorphic encryption");

    options.add_options()                                                                              //
        ("k,k_bits", "Bit width for keysize", cxxopts::value<int>())                                   //
        ("pub", "File for public key", cxxopts::value<std::string>())                                  //
        ("priv", "File for private key", cxxopts::value<std::string>())                                //
        ("u,u_vector", "File for u vector description", cxxopts::value<std::string>())                 //
        ("v,v_vector", "File for v vector description", cxxopts::value<std::string>())                 //
        ("eu,enc_u_vector", "File for encrypted u vector", cxxopts::value<std::string>())              //
        ("ev,enc_v_vector", "File for encrypted v vector", cxxopts::value<std::string>())              //
        ("result", "File for encrypted and unencrypted uv dot product", cxxopts::value<std::string>()) //
        ;

    options.parse(argc, argv);

    int k = options["k"].as<int>();
    std::string pub = options["pub"].as<std::string>(),
                priv = options["priv"].as<std::string>(),
                u = options["u"].as<std::string>(),
                v = options["v"].as<std::string>(),
                eu = options["eu"].as<std::string>(),
                ev = options["ev"].as<std::string>(),
                result = options["result"].as<std::string>();

    using namespace paillier;

    try
    {
        io::keygen(pub, priv, k);
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << e.what() << "\n";
        exit(1);
    }
    catch (...)
    {
        std::cerr << "Something major is broken...\n";
    }

    impl::PublicKey pub_key{};
    impl::PrivateKey priv_key{};
    {
        std::fstream pub_in(pub, pub_in.in);
        std::fstream priv_in(priv, priv_in.in);
        pub_in >> pub_key;
        priv_in >> priv_key;
    }

    auto u_vec = sdp::read_vector<impl::PlainText>(u);
    auto v_vec = sdp::read_vector<impl::PlainText>(v);

    auto eu_vec = sdp::map<impl::PlainText, impl::CipherText>(u_vec, [&pub_key](const impl::PlainText p) { return p.encrypt(pub_key); });

    return 0;
}
