// Copyright 2021 Adobe
// All Rights Reserved.
//
// NOTICE: Adobe permits you to use, modify, and distribute this file in accordance with the terms
// of the Adobe license agreement accompanying it.

// identity
#include "orc/parse_file.hpp"

// application config
#include "orc/features.hpp"

// stdc++
#include <bit>
#include <cstdio>

// system
#include <fcntl.h> // open
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h> // close

// application
#include "orc/ar.hpp"
#include "orc/fat.hpp"
#include "orc/mach_types.hpp"
#include "orc/macho.hpp"
#include "orc/orc.hpp"

/**************************************************************************************************/

namespace {

/**************************************************************************************************/

file_details detect_file(freader& s) {
    return temp_seek(s, [&] {
        std::uint32_t header;
        file_details result;

        result._offset = s.tellg();

        s.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (header == MH_MAGIC || header == MH_CIGAM || header == MH_MAGIC_64 ||
            header == MH_CIGAM_64) {
            result._format = file_details::format::macho;
        } else if (header == 'ra<!' || header == '!<ar') {
            result._format = file_details::format::ar;
        } else if (header == FAT_MAGIC || header == FAT_CIGAM || header == FAT_MAGIC_64 ||
                   header == FAT_CIGAM_64) {
            result._format = file_details::format::fat;
        }

        result._is_64_bit = header == MH_MAGIC_64 || header == MH_CIGAM_64 ||
                            header == FAT_MAGIC_64 || header == FAT_CIGAM_64;

        if constexpr (std::endian::native == std::endian::little) {
            result._needs_byteswap = header == MH_CIGAM || header == MH_CIGAM_64 ||
                                     header == FAT_CIGAM || header == FAT_CIGAM_64 ||
                                     header == 'ra<!';
        } else {
            result._needs_byteswap = header == MH_MAGIC || header == MH_MAGIC_64 ||
                                     header == FAT_MAGIC || header == FAT_MAGIC_64 ||
                                     header == '!<ar';
        }

        if (result._format == file_details::format::macho) {
            std::uint32_t cputype{0};
            s.read(reinterpret_cast<char*>(&cputype), sizeof(cputype));
            if (result._needs_byteswap) {
                endian_swap(cputype);
            }
            assert(((cputype & CPU_ARCH_ABI64) != 0) == result._is_64_bit);
            if (cputype == CPU_TYPE_X86) {
                result._arch = arch::x86;
            } else if (cputype == CPU_TYPE_X86_64) {
                result._arch = arch::x86_64;
            } else if (cputype == CPU_TYPE_ARM) {
                result._arch = arch::arm;
            } else if (cputype == CPU_TYPE_ARM64) {
                result._arch = arch::arm64;
            } else if (cputype == CPU_TYPE_ARM64_32) {
                result._arch = arch::arm64;
            } else {
                cerr_safe([&](auto& s) {
                    s << "WARN: Unknown Mach-O cputype\n";
                });
            }
        }

        return result;
    });
}

/**************************************************************************************************/

} // namespace

/**************************************************************************************************/
// See https://en.wikipedia.org/wiki/LEB128
std::uint32_t uleb128(freader& s) {
    std::uint32_t result{0};
    std::size_t shift{0};

    while (true) {
        auto c = s.get();
        if (shift <
            32) // shifts above 32 on uint32_t are undefined, but the s.get() needs to continue.
            result |= (c & 0x7f) << shift;
        if (!(c & 0x80)) return result;
        shift += 7;
    }
}

/**************************************************************************************************/

std::int32_t sleb128(freader& s) {
    std::int32_t result{0};
    std::size_t shift{0};
    bool sign{false};

    while (true) {
        auto c = s.get();
        result |= (c & 0x7f) << shift;
        shift += 7;
        if (!(c & 0x80)) {
            sign = c & 0x40;
            break;
        }
    }

    constexpr auto size_k{sizeof(result) * 8};

    if (sign && shift < size_k) {
        result |= -(1 << shift);
    }

    return result;
}

/**************************************************************************************************/

void parse_file(std::string_view object_name,
                const object_ancestry& ancestry,
                freader& s,
                std::istream::pos_type end_pos,
                callbacks callbacks) {
    auto detection = detect_file(s);

    // append this object name to the ancestry
    object_ancestry new_ancestry = ancestry;
    new_ancestry.emplace_back(empool(object_name));

    switch (detection._format) {
        case file_details::format::unknown:
            throw std::runtime_error("unknown format");
        case file_details::format::macho:
            return read_macho(std::move(new_ancestry), s, end_pos, std::move(detection),
                              std::move(callbacks));
        case file_details::format::ar:
            return read_ar(std::move(new_ancestry), s, end_pos, std::move(detection),
                           std::move(callbacks));
        case file_details::format::fat:
            return read_fat(std::move(new_ancestry), s, end_pos, std::move(detection),
                            std::move(callbacks));
    }
}

/**************************************************************************************************/

namespace {

/**************************************************************************************************/

auto make_shared_fd(const std::filesystem::path& p) {
    auto deleter = [](int* x) { close(*x); };
    auto fd = open(p.string().c_str(), O_RDONLY);
    return std::shared_ptr<int>(new int(fd), std::move(deleter));
}

auto filesize(int fd) {
    struct stat s;
    if (fstat(fd, &s) == -1) throw std::runtime_error("bad fstat"); // better error here?
    return s.st_size;
}

/**************************************************************************************************/

} // namespace

/**************************************************************************************************/

file_descriptor::file_descriptor(const std::filesystem::path& p) : _fd{make_shared_fd(p)} {}

/**************************************************************************************************/

mmap_buffer::mmap_buffer(int fd, std::size_t start, std::size_t end) {
    auto size = end - start;
    void* ptr = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, start);
    if (ptr == MAP_FAILED) throw std::runtime_error("bad mmap"); // better error here?
    auto deleter = [_sz = size](void* x) { munmap(x, _sz); };
    _buffer = std::shared_ptr<char>(static_cast<char*>(ptr), std::move(deleter));
}

/**************************************************************************************************/

mmap_buffer::mmap_buffer(int fd) : mmap_buffer(fd, 0, filesize(fd)) {}

/**************************************************************************************************/

filebuf::filebuf(const std::filesystem::path& p) : _descriptor{p}, _buffer{*_descriptor} {}

/**************************************************************************************************/

auto filebuf::remmap(std::size_t start, std::size_t end) {
    const auto page_size = sysconf(_SC_PAGESIZE);
    const auto start_page = start / page_size;
    const auto start_page_offset = start_page * page_size;
    const auto end_page = end / page_size + 1;
    const auto end_page_offset = end_page * page_size;

    assert(start < end);
    assert(start_page_offset <= start);
    assert(end_page_offset >= end);

    filebuf result;
    result._descriptor = _descriptor;
    result._buffer = mmap_buffer(*_descriptor, start_page_offset, end_page_offset);
    return result;
}

/**************************************************************************************************/

freader::freader(const std::filesystem::path& p)
    : _filebuf(p), _f(_filebuf.get()), _p(_f), _l(_p + std::filesystem::file_size(p)) {}

/**************************************************************************************************/

freader freader::subbuf(std::size_t end_pos) const {
    freader result(*this);
    auto pos = _p - _f;
    auto new_size = end_pos - pos;
    //auto size = _l - _f;
    result._filebuf = result._filebuf.remmap(pos, end_pos);
    // recalculate the new _p given the page offset of the buffer
    result._f = result._filebuf.get();
    result._p = _f - pos;
    result._l = _f + new_size;
    return result;
}

/**************************************************************************************************/
