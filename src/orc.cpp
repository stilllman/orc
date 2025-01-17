// Copyright 2021 Adobe
// All Rights Reserved.
//
// NOTICE: Adobe permits you to use, modify, and distribute this file in accordance with the terms
// of the Adobe license agreement accompanying it.

// identity
#include "orc/orc.hpp"

// stdc++
#include <array>
#include <cxxabi.h>
#include <filesystem>
#include <fstream>
#include <list>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>

// stlab
#include <stlab/concurrency/default_executor.hpp>
#include <stlab/concurrency/future.hpp>
#include <stlab/concurrency/serial_queue.hpp>
#include <stlab/concurrency/utility.hpp>

// toml++
#include <toml++/toml.h>

// tbb
#include <tbb/concurrent_unordered_map.h>

// application
#include "orc/dwarf.hpp"
#include "orc/features.hpp"
#include "orc/macho.hpp"
#include "orc/memory.hpp"
#include "orc/object_file_registry.hpp"
#include "orc/parse_file.hpp"
#include "orc/settings.hpp"
#include "orc/str.hpp"
#include "orc/string_pool.hpp"
#include "orc/task_system.hpp"

/**************************************************************************************************/

std::mutex& ostream_safe_mutex() {
    static std::mutex m;
    return m;
}

/**************************************************************************************************/

namespace {

/**************************************************************************************************/

std::string_view path_to_symbol(std::string_view path) {
    // lop off the prefix. In most cases it'll be "::[u]::" - in some it'll be just "::[u]" (in
    // which case there is no symbol path - it's a top-level compilation unit.) We assume the path
    // here starts with one of the two options above, and so return the result based on the string
    // length.

    return path.size() < 7 ? std::string_view() : path.substr(7);
}

/**************************************************************************************************/
bool type_equivalent(const attribute& x, const attribute& y);
dw::at find_attribute_conflict(const attribute_sequence& x, const attribute_sequence& y) {
    auto yfirst = y.begin();
    auto ylast = y.end();

    for (const auto& xattr : x) {
        auto name = xattr._name;
        if (nonfatal_attribute(name)) continue;

        auto yfound = std::find_if(yfirst, ylast, [&](auto& x) { return name == x._name; });
        if (yfound == ylast) return name;

        const auto& yattr = *yfound;

        if (name == dw::at::type && type_equivalent(xattr, yattr))
            continue;
        else if (xattr == yattr)
            continue;

        return name;
    }

    // Find and flag any nonfatal attributes that exist in y but not in x
    const auto xfirst = x.begin();
    const auto xlast = x.end();
    for (; yfirst != ylast; ++yfirst) {
        const auto& name = yfirst->_name;
        if (nonfatal_attribute(name)) continue;
        auto xfound = std::find_if(xfirst, xlast, [&](auto& x) { return name == x._name; });
        if (xfound == xlast) return name;
    }

    return dw::at::none; // they're "the same"
}

/**************************************************************************************************/

bool type_equivalent(const attribute& x, const attribute& y) {
    // types are pretty convoluted, so we pull their comparison out here in an effort to
    // keep it all in a developer's head.

    if (x.has(attribute_value::type::reference) && y.has(attribute_value::type::reference) &&
        x.reference() == y.reference()) {
        return true;
    }

    if (x.has(attribute_value::type::string) && y.has(attribute_value::type::string) &&
        x.string_hash() == y.string_hash()) {
        return true;
    }

    // Type mismatch.
    return false;
}

/**************************************************************************************************/

void update_progress() {
    if (!settings::instance()._show_progress) return;

    std::size_t done = globals::instance()._die_analyzed_count;
    std::size_t total = globals::instance()._die_processed_count;
    std::size_t percentage = static_cast<double>(done) / total * 100;

    cout_safe([&](auto& s) {
        s << '\r' << done << "/" << total << "  " << percentage << "%; ";
        s << globals::instance()._odrv_count << " violation(s) found";
        s << "          "; // 10 spaces of overprint to clear out any previous lingerers
    });
}

/**************************************************************************************************/

auto& unsafe_global_die_collection() {
    static decltype(auto) collection_s = orc::make_leaky<std::list<dies>>();
    return collection_s;
}

template <class F>
auto with_global_die_collection(F&& f) {
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);
    return f(unsafe_global_die_collection());
}

/**************************************************************************************************/

auto& global_die_map() {
    static decltype(auto) map_s = orc::make_leaky<tbb::concurrent_unordered_map<std::size_t, die*>>();
    return map_s;
}

/**************************************************************************************************/

void register_dies(dies die_vector) {
    // This is a list so the die vectors don't move about. The dies become pretty entangled as they
    // point to one another by reference, and the odr_map itself stores const pointers to the dies
    // it registers. Thus, we move our incoming die_vector to the end of this list, and all the
    // pointers we use will stay valid for the lifetime of the application.
    dies& dies = *with_global_die_collection([&](auto& collection) {
        collection.push_back(std::move(die_vector));
        return --collection.end();
    });

    globals::instance()._die_processed_count += dies.size();

    for (auto& d : dies) {
        if (d._skippable) continue;
#if 0
        if (settings::instance()._print_symbol_paths) {
            // This is all horribly broken, especially now that we're calling this from multiple threads.
            static pool_string last_object_file_s;

            cout_safe([&](auto& s){
                if (d._object_file != last_object_file_s) {
                    last_object_file_s = d._object_file;
                    s << '\n' << last_object_file_s << '\n';
                }

                s << (should_skip ? 'S' : 'R') << " - 0x";
                s.width(8);
                s.fill('0');
                s << std::hex << d._debug_info_offset << std::dec << " " << d._path << '\n';
            });
        }
#endif

        //
        // At this point we know we're going to register the die. Hereafter belongs
        // work exclusive to DIEs getting registered/odr-enforced.
        //

        auto result = global_die_map().insert(std::make_pair(d._hash, &d));
        if (result.second) {
            ++globals::instance()._unique_symbol_count;
            continue;
        }

        constexpr auto mutex_count_k = 67; // prime; to help reduce any hash bias
        static std::mutex mutexes_s[mutex_count_k];
        std::lock_guard<std::mutex> lock(mutexes_s[d._hash % mutex_count_k]);

        die& d_in_map = *result.first->second;
        d._next_die = d_in_map._next_die;
        d_in_map._next_die = &d;
    }

    globals::instance()._die_analyzed_count += dies.size();

    update_progress();
}

/**************************************************************************************************/

struct cmdline_results {
    std::vector<std::filesystem::path> _file_object_list;
    bool _ld_mode{false};
    bool _libtool_mode{false};
};

/**************************************************************************************************/

struct work_counter {
    struct state {
        void increment() {
            {
                std::lock_guard<std::mutex> lock(_m);
                ++_n;
            }
            _c.notify_all();
        }

        void decrement() {
            {
                std::lock_guard<std::mutex> lock(_m);
                --_n;
            }
            _c.notify_all();
        }

        void wait() {
            std::unique_lock<std::mutex> lock(_m);
            if (_n == 0) return;
            _c.wait(lock, [&] { return _n == 0; });
        }

        std::mutex _m;
        std::condition_variable _c;
        std::size_t _n{0};
    };

    using shared_state = std::shared_ptr<state>;

    friend struct token;

public:
    work_counter() : _impl{std::make_shared<state>()} {}

    struct token {
        token(shared_state w) : _w(std::move(w)) { _w->increment(); }
        token(const token& t) : _w{t._w} { _w->increment(); }
        token(token&& t) = default;
        ~token() {
            if (_w) _w->decrement();
        }

    private:
        shared_state _w;
    };

    auto working() { return token(_impl); }

    void wait() { _impl->wait(); }

private:
    shared_state _impl;

    void increment() { _impl->increment(); }
    void decrement() { _impl->decrement(); }
};

/**************************************************************************************************/

auto& work() {
    static work_counter _work;
    return _work;
}

/**************************************************************************************************/

void do_work(std::function<void()> f) {
    auto doit = [](auto&& f) {
        try {
            f();
        } catch (const std::exception& error) {
            cerr_safe([&](auto& s) { s << error.what() << '\n'; });
        } catch (...) {
            cerr_safe([&](auto& s) { s << "unknown exception caught" << '\n'; });
        }
    };

    if (!settings::instance()._parallel_processing) {
        doit(f);
        return;
    }

    static orc::task_system system;

    system([_work_token = work().working(), _doit = doit, _f = std::move(f)] { _doit(_f); });
}

/**************************************************************************************************/

const char* problem_prefix() { return settings::instance()._graceful_exit ? "warning" : "error"; }

/**************************************************************************************************/

attribute_sequence fetch_attributes_for_die(const die& d) {
    auto dwarf = dwarf_from_macho(d._ofd_index, register_dies_callback());

    auto [die, attributes] = dwarf.fetch_one_die(d._debug_info_offset);
    assert(die._tag == d._tag);
    assert(die._arch == d._arch);
    assert(die._has_children == d._has_children);
    assert(die._debug_info_offset == d._debug_info_offset);
    return std::move(attributes);
}

/**************************************************************************************************/

} // namespace

/**************************************************************************************************/

odrv_report::odrv_report(std::string_view symbol, const die* list_head)
    : _symbol(symbol), _list_head(list_head) {
    assert(_list_head->_conflict);

    // Construct a map of unique definitions of the conflicting symbol.

    if (_conflict_map.empty()) {
        for (const die* next_die = _list_head; next_die; next_die = next_die->_next_die) {
            std::size_t hash = next_die->_fatal_attribute_hash;
            if (_conflict_map.count(hash)) continue;
            conflict_details details;
            details._die = next_die;
            details._attributes = fetch_attributes_for_die(*details._die);
            _conflict_map[hash] = std::move(details);
        }
    }

    assert(_conflict_map.size() > 1);

    // Derive the ODRV category.

    auto& front = _conflict_map.begin()->second;
    auto& back = (--_conflict_map.end())->second;
    _name = find_attribute_conflict(front._attributes, back._attributes);
}

/**************************************************************************************************/

std::string odrv_report::category() const {
    return to_string(_conflict_map.begin()->second._die->_tag) + std::string(":") +
           to_string(_name);
}

/**************************************************************************************************/
bool filter_report(const odrv_report& report)
{
    std::string odrv_category = report.category();

    // Decide if we should report or ignore.

    auto& settings = settings::instance();
    bool do_report{true};

    if (!settings._violation_ignore.empty()) {
        // Report everything except the stuff on the ignore list
        do_report = !sorted_has(settings._violation_ignore, odrv_category);
    } else if (!settings._violation_report.empty()) {
        // Report nothing except the the stuff on the report list
        do_report = sorted_has(settings._violation_report, odrv_category);
    }

    return do_report;
}


/**************************************************************************************************/

std::ostream& operator<<(std::ostream& s, const odrv_report& report) 
{    
    const std::string_view& symbol = report._symbol;
    std::string odrv_category = report.category();

    s << problem_prefix() << ": ODRV (" << odrv_category << "); conflict in `"
      << (symbol.data() ? demangle(symbol.data()) : "<unknown>") << "`\n";
    for (const auto& entry : report.conflict_map()) {
        s << (*entry.second._die) << entry.second._attributes << '\n';
    }
    s << "\n";

    return s;
}

/**************************************************************************************************/

die* enforce_odrv_for_die_list(die* base, std::vector<odrv_report>& results) {
    std::vector<die*> dies;
    for (die* ptr = base; ptr; ptr = ptr->_next_die) {
        dies.push_back(ptr);
    }
    assert(!dies.empty());
    if (dies.size() == 1) return base;

    // Theory: if multiple copies of the same source file were compiled,
    // the ancestry might not be unique. We assume that's an edge case
    // and the ancestry is unique.
    std::sort(dies.begin(), dies.end(), [](const die* a, const die* b) {
        return object_file_ancestry(a->_ofd_index) < object_file_ancestry(b->_ofd_index);
    });

    bool conflict{false};
    for (size_t i = 1; i < dies.size(); ++i) {
        // Re-link the die list to match the sorted order.
        dies[i - 1]->_next_die = dies[i];

        if (!conflict) {
            conflict = dies[i - 1]->_fatal_attribute_hash != dies[i]->_fatal_attribute_hash;
        }
    }
    dies.back()->_next_die = nullptr;

    if (!conflict) return dies.front();

    dies[0]->_conflict = true;

    odrv_report report{path_to_symbol(base->_path.view()), dies[0]};

    static std::mutex result_mutex;
    std::lock_guard<std::mutex> lock(result_mutex);
    results.push_back(report);

    return dies.front();
}

/**************************************************************************************************/
#if ORC_FEATURE(UNIQUE_SYMBOL_DIES)
auto unique_symbol_die_count() {
    std::size_t count{0};
    for (const auto& entry : global_die_map()) {
        for (const die* ptr = entry.second; ptr; ptr = ptr->_next_die) {
            ++count;
        }
    }
    return count;
}
#endif // ORC_FEATURE(UNIQUE_SYMBOL_DIES)
/**************************************************************************************************/

std::vector<odrv_report> orc_process(const std::vector<std::filesystem::path>& file_list) {
    // First stage: process all the DIEs
    for (const auto& input_path : file_list) {
        do_work([_input_path = input_path] {
            if (!exists(_input_path)) {
                throw std::runtime_error("file " + _input_path.string() + " does not exist");
            }

            freader input(_input_path);
            callbacks callbacks = {
                register_dies,
                do_work,
            };

            parse_file(_input_path.string(), object_ancestry(), input, input.size(),
                       std::move(callbacks));
        });
    }

    work().wait();

#if ORC_FEATURE(UNIQUE_SYMBOL_DIES)
    globals::instance()._unique_symbol_die_count = unique_symbol_die_count();
#endif // ORC_FEATURE(UNIQUE_SYMBOL_DIES)

    // Second stage: review DIEs for ODRVs
    std::vector<odrv_report> result;

    for (auto& entry : global_die_map()) {
        do_work([&entry, &result]() mutable {
            entry.second = enforce_odrv_for_die_list(entry.second, result);
        });
    }

    work().wait();

    // Sort the ordrv_report
    std::sort(result.begin(), result.end(),
              [](const odrv_report& a, const odrv_report& b) { return a._symbol < b._symbol; });

    return result;
}

/**************************************************************************************************/

void orc_reset() {
    global_die_map().clear();
    with_global_die_collection([](auto& collection) { collection.clear(); });
}

/**************************************************************************************************/

const char* demangle(const char* x) {
    // The returned char* is good until the next call to demangle() on the same thread.
    // See: https://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html
    thread_local std::unique_ptr<char, void (*)(void*)> hold{nullptr, &free};
    int status = 0;
    char* p = abi::__cxa_demangle(x, nullptr, nullptr, &status);
    if (!p || status != 0) return x;
    hold.reset(p);
    return p;
}

/**************************************************************************************************/
