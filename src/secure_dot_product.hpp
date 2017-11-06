#ifndef PAILLIER_SECURE_DOT_PRODUCT_HPP
#define PAILLIER_SECURE_DOT_PRODUCT_HPP

#include <algorithm>
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

template <class T>
void write_vector(io::ssv path, const std::vector<T> &ts)
{
    std::fstream vector(path.data(), vector.out);
    for (const auto &t : ts)
    {
        vector << t << std::endl;
    }
}

template <class T, class U>
std::vector<U> map(std::vector<T> from, std::function<U(const T &)> f)
{
    std::vector<U> to;
    to.reserve(from.size());
    std::transform(from.begin(), from.end(), std::back_inserter(to), f);
    return to;
}

template <class T, class U, class V>
std::vector<V> pairwise_map(const std::vector<T> &ts, const std::vector<U> &us, std::function<V(const T &, const U &)> f)
{
    std::vector<V> vs;
    vs.reserve(std::min(ts.size(), us.size()));
    std::transform(ts.begin(), ts.end(), us.begin(), std::back_inserter(vs), f);
    return vs;
}

template <class T, class U>
U reduce(const std::vector<T> &ts, std::function<U(const U &, const T &)> f, U init)
{
    return std::accumulate(ts.begin(), ts.end(), init, f);
}

// sdp
}
// paillier
}

#endif // PAILLIER_SECURE_DOT_PRODUCT_HPP
