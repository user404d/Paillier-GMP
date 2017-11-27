#include <algorithm>
#include "cxxopts.hpp"
#include <cinttypes>
#include <fstream>
#include <future>
#include <iostream>
#include <paillier.hpp>
#include <string>
#include <vector>

template <typename T>
std::vector<T> read_vector(paillier::io::ssv vector_path)
{
    std::fstream vector(vector_path.data(), vector.in);
    return {std::istream_iterator<T>(vector), {}};
}

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

    const auto u_vec = read_vector<impl::PlainText>(u), v_vec = read_vector<impl::PlainText>(v);

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

    const auto f_encrypt = [=](const impl::PlainText &p) {
        static const auto encrypt = [pub_key](const impl::PlainText &p) { return p.encrypt(pub_key); };
        return std::async(encrypt, p);
    };

    const auto f_mult = [=](const std::shared_future<impl::CipherText> &f_c, const impl::PlainText &p) {
        static const auto mult = [pub_key](const impl::CipherText &c, const impl::PlainText &p) {
            return c.mult(p.text, pub_key);
        };
        return std::async(mult, f_c.get(), p);
    };

    const auto add = [pub_key](const impl::CipherText &acc, const std::shared_future<impl::CipherText> &f_c) {
        return acc.add(f_c.get(), pub_key);
    };

    const auto write = [](io::ssv out, const std::vector<std::shared_future<impl::CipherText>> &v_f_c) {
        std::fstream vector(out.data(), vector.out);
        for (const auto &f_c : v_f_c)
        {
            vector << f_c.get() << std::endl;
        }
    };

    std::vector<std::shared_future<impl::CipherText>> f_eu_vec, f_ev_vec, f_ev_u_vec;

    std::transform(u_vec.begin(), u_vec.end(), std::back_inserter(f_eu_vec), f_encrypt);
    std::transform(v_vec.begin(), v_vec.end(), std::back_inserter(f_ev_vec), f_encrypt);

    std::thread(write, eu, f_eu_vec).detach();
    std::thread(write, ev, f_ev_vec).detach();

    std::transform(f_ev_vec.begin(), f_ev_vec.end(), u_vec.begin(), std::back_inserter(f_ev_u_vec), f_mult);

    const auto e_dot_prod = std::accumulate(f_ev_u_vec.begin(), f_ev_u_vec.end(), impl::PlainText(0).encrypt(pub_key), add);
    const auto dot_prod = e_dot_prod.decrypt(priv_key);

    {
        std::fstream res(result, res.out);
        res << e_dot_prod << "\n"
            << dot_prod << std::endl;
    }

    return 0;
}
