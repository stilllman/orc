// Copyright 2021 Adobe
// All Rights Reserved.
//
// NOTICE: Adobe permits you to use, modify, and distribute this file in accordance with the terms
// of the Adobe license agreement accompanying it.

#pragma once

// stdc++
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <type_traits>

// application
#include "orc/dwarf_structs.hpp"
#include "orc/hash.hpp"
#include "orc/string_pool.hpp"

/**************************************************************************************************/
// read-only file descriptor
struct file_descriptor {
    file_descriptor() = default;
    explicit file_descriptor(const std::filesystem::path& p);
    explicit operator bool() const { return static_cast<bool>(_fd); }
    auto operator*() const { return *_fd; }

private:
    std::shared_ptr<int> _fd;
};

/**************************************************************************************************/

struct mmap_buffer {
    mmap_buffer() = default;
    explicit mmap_buffer(int fd);
    explicit mmap_buffer(int fd, std::size_t start, std::size_t end);
    explicit operator bool() const { return static_cast<bool>(_buffer); }
    const char* get() const { return _buffer.get(); }

private:
    std::shared_ptr<char> _buffer;
};

/**************************************************************************************************/

struct filebuf {
    explicit filebuf() = default;
    explicit filebuf(const std::filesystem::path& p);
    explicit operator bool() const { return _descriptor && _buffer; }
    const char* get() const { return _buffer.get(); }
    auto remmap(std::size_t start, std::size_t end);

private:
    file_descriptor _descriptor;
    mmap_buffer _buffer;
};

/**************************************************************************************************/
// very minimal file reader. Uses mmap to bring the file into memory, and subsequently unmaps it
// when the reader destructs. Doesn't do any kinds of bounds checking while reading (that's a
// responsibility of the user at this point, but we could change it if it's more valuable to do so
// here.)
struct freader {
    using off_type = std::istream::off_type;

    explicit freader(const std::filesystem::path& p);

    // `<=` here because sometimes we jump to one past the end of the buffer right before stopping.
    explicit operator bool() const { return static_cast<bool>(_filebuf) && _p <= _l; }

    std::size_t size() const { return _l - _p; }

    std::size_t tellg() const { return _p - _f; }

    void seekg(std::istream::off_type offset) {
        assert(*this);
        _p = _f + offset;
    }

    void seekg(std::istream::off_type offset, std::ios::seekdir dir) {
        assert(*this);
        switch (dir) {
            case std::ios::beg: {
                _p = _f + offset;
            } break;
            case std::ios::cur: {
                _p += offset;
            } break;
            case std::ios::end: {
                _p = _f + (size() - offset);
            } break;
            default: {
                // GNU's libstdc++ has an end-of-options marker that the compiler
                // will complain about as being unhandled here. It should *never*
                // be used as a valid value for this enumeration.
                assert(false);
            } break;
        }
    }

    void read(char* p, std::size_t n) {
        assert(*this);
        std::memcpy(p, _p, n);
        _p += n;
    }

    char get() {
        assert(*this);
        return *_p++;
    }

    std::string_view read_c_string_view() {
        assert(*this);
        auto f = _p;
        for (; *_p; ++_p) {
        }
        auto n = _p++ - f;
        return std::string_view(f, n);
    }

    // creates a new _buffer using the same mmapped pages, but limited to the range
    // [tellg(), end_pos), allowing for the parent freader to fall out of scope and
    // free up unused memory.
    freader subbuf(std::size_t end_pos) const;

private:
    filebuf _filebuf;
    const char* _f{0};
    const char* _p{0};
    const char* _l{0};
};

/**************************************************************************************************/
// temp_seek will move the read pointer of the incoming reader to the specified location, execute
// the lambda, and then reset the read points to the location it was at when the routine began.
// the read pointer will be correctly reset even if the lambda throws.
template <typename F>
auto temp_seek(freader& s, std::istream::off_type offset, std::ios::seekdir dir, F&& f) {
    struct posmark {
        explicit posmark(freader& s) : _s{s}, _pos{_s.tellg()} {}
        ~posmark() { _s.seekg(_pos); }

    private:
        freader& _s;
        std::size_t _pos;
    } pm(s);

    s.seekg(offset, dir);

    if constexpr (std::is_same<std::invoke_result_t<F>, void>::value) {
        std::forward<F>(f)();
    } else {
        return std::forward<F>(f)();
    }
}

template <typename F>
auto temp_seek(freader& s, std::istream::off_type offset, F&& f) {
    return temp_seek(s, offset, std::ios::beg, std::forward<F>(f));
}

template <typename F>
auto temp_seek(freader& s, F&& f) {
    return temp_seek(s, 0, std::ios::cur, std::forward<F>(f));
}

template <typename F>
auto read_exactly(freader& s, std::size_t size, F&& f) {
    auto start = s.tellg();
    if constexpr (std::is_same<std::invoke_result_t<F, std::size_t>, void>::value) {
        std::forward<F>(f)(size);
        assert(s.tellg() == start + size);
        if (s.tellg() != start + size) throw std::runtime_error("read_exactly failure");
    } else {
        auto result = std::forward<F>(f)(size);
        assert(s.tellg() == start + size);
        if (s.tellg() != start + size) throw std::runtime_error("read_exactly failure");
        return result;
    }
}

/**************************************************************************************************/

struct file_details {
    enum class format {
        unknown,
        macho,
        ar,
        fat,
    };
    std::size_t _offset{0};
    format _format{format::unknown};
    arch _arch{arch::unknown};
    bool _is_64_bit{false};
    bool _needs_byteswap{false};
};

/**************************************************************************************************/

template <typename T>
void endian_swap(T& c) {
    char* first = reinterpret_cast<char*>(&c);
    char* last = first + sizeof(T);
    while (first != last) {
        --last;
        std::swap(*first, *last);
        ++first;
    }
}

/**************************************************************************************************/

template <typename T>
T read_pod(freader& s) {
    T x;
    s.read(reinterpret_cast<char*>(&x), sizeof(T));
    return x;
}

template <>
inline bool read_pod(freader& s) {
    char x;
    s.read(reinterpret_cast<char*>(&x), 1);
    return x ? true : false;
}
/**************************************************************************************************/

std::uint32_t uleb128(freader& s);
std::int32_t sleb128(freader& s);

/**************************************************************************************************/
/*
    For functions that take values by rvalue reference (aka sink functions), it can be helpful to be
    explicit about the object being passed in. In such cases, the object can only be moved or
    copied. C++ already provides a `move` routine; this is the `copy` equivalent. It is more
    helpful than passing T(x) (which would create a copy of x) because, at a minimum, it is more
    explicit about the intent of the call.
*/
template <typename T>
constexpr std::decay_t<T> copy(T&& value) noexcept(noexcept(std::decay_t<T>{
    static_cast<T&&>(value)})) {
    static_assert(!std::is_same<std::decay_t<T>, T>::value, "explicit copy of rvalue.");
    return std::decay_t<T>{static_cast<T&&>(value)};
}

/**************************************************************************************************/

using register_dies_callback = std::function<void(dies)>;
using do_work_callback = std::function<void(std::function<void()>)>;
using empool_callback = std::function<pool_string(std::string_view)>;

struct callbacks {
    register_dies_callback _register_die;
    do_work_callback _do_work;
};

void parse_file(std::string_view object_name,
                const object_ancestry& ancestry,
                freader& s,
                std::istream::pos_type end_pos,
                callbacks callbacks);

/**************************************************************************************************/
