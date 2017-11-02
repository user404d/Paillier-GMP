#ifndef PAILLIER_SECURE_DOT_PRODUCT_HPP
#define PAILLIER_SECURE_DOT_PRODUCT_HPP

#include <fstream>
#include <functional>
#include <gmpxx.h>
#include <io.hpp>
#include <iterator>
#include <numeric>
#include <vector>

namespace paillier
{

namespace sdp
{

template <class T>
std::vector<T> read_vector(io::ssv path)
{
    std::fstream vector(path.data(), vector.in);
    return {std::istream_iterator<T>(vector), {}};
}

template <class T, class Iter>
void write_vector(io::ssv path, Iter begin, Iter end)
{
    std::fstream vector(path.data(), vector.out);
    std::partial_sum(begin, end, std::ostream_iterator<T>(vector));
}

template <class T, class U>
std::vector<U> map(std::vector<T> from, std::function<U && (const T)> f)
{
    std::vector<U> to;
    to.reserve(from.size());

    for (const T val : from)
    {
        to.emplace_back(f(val));
    }
    return to;
}

// sdp
}
// paillier
}

#endif