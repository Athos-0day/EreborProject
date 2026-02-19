#ifndef HKD_HPP
#define HKD_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "exceptions.hpp"
#include "secure_string.hpp"
#include "seed.hpp"

/**
 * @file hkd.hpp
 * @brief Declaration of the HKD (Hierarchical Key Derivation) class compliant with BIP-32.
 * @author Athos-0day
 * @date 2026
 */

namespace Erebor {

    /**
     * @class HKD
     * @brief Implements BIP-32 compliant hierarchical deterministic key derivation, 
     * enabling secure generation and management of extended private keys.
     */
    class HKD {
    public:
        /// @brief BIP-32 Hardened derivation offset (2^31)
        static constexpr uint32_t HARDENED_OFFSET = 0x80000000;

        /** * @brief Represents a BIP-32 extended key composed of 
         * a 32-byte private key and its associated 32-byte chain code used 
         * for hierarchical derivation.
         */
        struct ExtendedKey {
            std::array<uint8_t, 32> key;       // private key (k)
            std::array<uint8_t, 32> chainCode; // entropy (c)
            
            void zeroize() {
                secure_memzero(key.data(), key.size());
                secure_memzero(chainCode.data(), chainCode.size());
            }
        };

        /**
         * @brief Derives the Master Node from the 512 bits seed.
         * @param seed the 512 bits seed.
         * @return Master Node.
         * @throw CryptoException If HMAC-SHA512 fails.
         */
        static ExtendedKey computeMasterNode(const Erebor::Seed::Seed512& seed);

        /**
         * @brief Derives a child key from a parent ExtendedKey.
         * * Applies the BIP-32 CKD (Child Key Derivation) function. 
         * Handles both normal and hardened derivation based on the index.
         * * @param parent The parent ExtendedKey.
         * @param index The child index (indices >= 0x80000000 are hardened).
         * @return The derived child ExtendedKey.
         * @throw CryptoException If the derived key is invalid (statistically highly improbable).
         */
        static ExtendedKey deriveChildKey(const ExtendedKey& parent, uint32_t index);

        /**
         * @brief Parses a BIP-32/BIP-44 path and derives the final key recursively.
         * * Example path: "m/44'/0'/0'/0/0"
         * * @param master The root Master Node.
         * @param path The string representation of the derivation path.
         * @return The final ExtendedKey at the end of the path.
         * @throw std::invalid_argument If the path format is incorrect.
         */
        static ExtendedKey derivePath(const ExtendedKey& master, const std::string& path);

        /**
         * @brief Utility to check if an index is in the hardened range.
         */
        static constexpr bool isHardened(uint32_t index) {
            return (index & HARDENED_OFFSET) != 0;
        }

        /**
         * @brief Utility to apply the hardened offset to a standard index.
         */
        static constexpr uint32_t hardenIndex(uint32_t index) {
            return index | HARDENED_OFFSET;
        }
    };

} // namespace Erebor

#endif // HKD_HPP