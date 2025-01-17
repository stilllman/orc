// Copyright 2021 Adobe
// All Rights Reserved.
//
// NOTICE: Adobe permits you to use, modify, and distribute this file in accordance with the terms
// of the Adobe license agreement accompanying it.

// identity
#include "orc/string_pool.hpp"

// stdc++
#include <cassert>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// tbb
#include <tbb/concurrent_unordered_map.h>

// application
#include "orc/features.hpp"
#include "orc/hash.hpp"
#include "orc/memory.hpp"

/*static*/ std::string_view pool_string::default_view("");

/**************************************************************************************************/

namespace {

/**************************************************************************************************/

std::size_t string_view_hash(std::string_view s) { return orc::murmur3_64(s.data(), static_cast<std::uint32_t>(s.length())); }

/**************************************************************************************************/

// Data is backed and not aligned.
// Before the _data pointer:
//      'uint32_t' length of string
//      'size_t' hash
// The _data pointer is returned to a null terminated string, to make debugging easier
// get_size() and get_hash() unpack this data as needed.
//
struct pool {
    char* _p{nullptr};
    std::size_t _n{0};
    using ponds_type = std::vector<std::unique_ptr<char[]>>;
#if ORC_FEATURE(LEAKY_MEMORY)
    ponds_type& _ponds{orc::make_leaky<ponds_type>()};
#else
    ponds_type _ponds{orc::make_leaky<ponds_type>()};
#endif // ORC_FEATURE(LEAKY_MEMORY)

    const char* empool(std::string_view incoming) {
        constexpr auto default_min_k = 16 * 1024 * 1024; // 16MB
        const uint32_t sz = (uint32_t)incoming.size();
        const uint32_t tsz = sz + sizeof(uint32_t) + sizeof(size_t) + 1;

        if (_n < tsz) {
            _n = std::max<std::size_t>(default_min_k, tsz);
            _ponds.push_back(std::make_unique<char[]>(_n));
            _p = _ponds.back().get();
        }
        const std::size_t h = string_view_hash(incoming);
        // Memory isn't aligned - need to memcpy to pack the data
        std::memcpy(_p, &sz, sizeof(uint32_t));
        std::memcpy(_p + sizeof(uint32_t), &h, sizeof(size_t));
        std::memcpy(_p + sizeof(uint32_t) + sizeof(size_t), incoming.data(), sz);
        *(_p + tsz - 1) = 0; // null terminate for debugging

        const char* result = _p + sizeof(uint32_t) + sizeof(size_t);
        _n -= tsz;
        _p += tsz;
        return result;
    }
};
} // namespace

/**************************************************************************************************/

std::size_t pool_string::get_size(const char* d) {
    assert(d);
    const void* bytes = d - sizeof(std::uint32_t) - sizeof(std::size_t);
    std::uint32_t s = orc::unaligned_read<std::uint32_t>(bytes);
    assert(s > 0);      // required, else should have been _data == nullptr
    assert(s < 100000); // sanity check
    return s;
}

std::size_t pool_string::get_hash(const char* d) {
    assert(d);
    const void* bytes = d - sizeof(std::size_t);
    return orc::unaligned_read<std::size_t>(bytes);
}

pool_string empool(std::string_view src) {
    // A pool_string is empty iff _data = nullptr
    // So this creates an empty pool_string (as opposed to an empty string_view, where
    // default_view would be returned.)
    if (src.empty()) return pool_string(nullptr);

    static decltype(auto) keys =
        orc::make_leaky<tbb::concurrent_unordered_map<size_t, const char*>>();

    const std::size_t h = string_view_hash(src);

    auto find_key = [&](size_t h) -> const char* {
        // This code doesn't work because there's a race condition where end() can change.
        // const auto it0 = keys.find(h);
        // if (it0 != keys.end()) {

        // But we never remove from the map, so if contains(), it is guaraneteed to find()
        if (keys.contains(h)) {
            return keys.find(h)->second;
        }
        return nullptr;
    };

    if (const char* c = find_key(h)) {
        pool_string ps(c);
        assert(ps.view() == src);
        return ps;
    }

    constexpr int pool_count_k = 23;
    static std::mutex pool_mutex[pool_count_k];
    const int index = h % pool_count_k;
    std::lock_guard<std::mutex> pool_guard(pool_mutex[index]);

    // Now that we have the lock, do the search again in case another thread empooled the string
    // while we were waiting for the lock.
    if (const char* c = find_key(h)) {
        pool_string ps(c);
        assert(ps.view() == src);
        return ps;
    }

    // Not already interned; empool it and add to the 'keys'
    // The pools are not threadsafe, so we need one per mutex
    static pool pools[pool_count_k];
    const char* ptr = pools[index].empool(src);
    assert(ptr);
    keys.insert(std::make_pair(h, ptr));

    return pool_string(ptr);
}

/**************************************************************************************************/
