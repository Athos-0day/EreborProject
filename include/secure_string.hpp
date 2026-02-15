/**
 * @file secure_string.hpp
 * @brief Memory-hardened container for cryptographic secrets.
 * @author Athos-0day
 * @date 2026
 */

#ifndef SECURE_STRING_HPP
#define SECURE_STRING_HPP

#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <cstring>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#endif

namespace Erebor {

    /**
     * @brief Optimization-resistant memory zeroization.
     */
    inline void secure_memzero(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;

#if defined(_WIN32) || defined(_WIN64)
        RtlSecureZeroMemory(ptr, size);
#elif defined(__STDC_LIB_EXT1__)
        memset_s(ptr, size, 0, size);
#else
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (size--) *p++ = 0;
        std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
    }

    /**
     * @brief Custom allocator ensuring internal reallocations are zeroized.
     * Prevents "ghost data" from remaining in RAM after vector growth.
     */
    template <typename T>
    struct zero_allocator {
        using value_type = T;
        zero_allocator() = default;
        template <class U> constexpr zero_allocator(const zero_allocator<U>&) noexcept {}

        T* allocate(std::size_t n) {
            if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
            if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) return p;
            throw std::bad_alloc();
        }

        void deallocate(T* p, std::size_t n) noexcept {
            secure_memzero(p, n * sizeof(T));
            std::free(p);
        }
    };

    /**
     * @class secure_string
     * @brief RAII container for mnemonics and keys. 
     * Deleted copy constructors prevent accidental secret duplication.
     */
    class secure_string {
    private:
        std::vector<char, zero_allocator<char>> buffer;

    public:
        secure_string() = default;

        explicit secure_string(const std::string& str) 
            : buffer(str.begin(), str.end()) {}

        secure_string(const char* str) {
            if (str) buffer.assign(str, str + std::strlen(str));
        }

        ~secure_string() = default; // Zeroization handled by allocator

        // Copying is prohibited to enforce the Single Source of Truth principle.
        secure_string(const secure_string&) = delete;
        secure_string& operator=(const secure_string&) = delete;

        secure_string(secure_string&&) noexcept = default;
        secure_string& operator=(secure_string&&) noexcept = default;

        // Data Access
        char* data() { return buffer.data(); }
        const char* data() const { return buffer.data(); }
        size_t size() const { return buffer.size(); }
        bool empty() const { return buffer.empty(); }

        void push_back(char c) { buffer.push_back(c); }

        /**
         * @brief Constant-time comparison to prevent timing side-channel attacks.
         */
        bool operator==(const secure_string& other) const {
            if (size() != other.size()) return false;
            volatile unsigned char diff = 0;
            for (size_t i = 0; i < size(); ++i) {
                diff |= (buffer[i] ^ other.buffer[i]);
            }
            return diff == 0;
        }
    };

} // namespace Erebor

#endif