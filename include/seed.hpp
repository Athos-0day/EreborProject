#ifndef SEED_HPP
#define SEED_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "exceptions.hpp"
#include "secure_string.hpp"

/**
 * @file seed.hpp
 * @brief Declaration of the Seed class compliant with BIP-39.
 * @author Athos-0day
 * @date 2026
 */

namespace Erebor {

    /**
     * @class Seed
     * @brief Generates and manages entropy and seed according to BIP-39.
     */
    class Seed {
        public:
            using Seed512 = std::array<uint8_t, 64>;

            /**
             * @brief Generate entropy (ENT) using a CSPRNG.
             * @param length Size of mnemonic phrase (12 or 24).
             * @return Generated entropy as byte array.
             * @throw ForbiddenSize If length is not 12 or 24.
             * @throw CryptoException If CSPRNG fails.
             */
            static std::array<uint8_t, 32> generateEntropy(std::size_t length);

            /**
             * @brief Compute the Checksum of the entropy
             * @param length Size of mnemonic phrase (12 or 24).
             * @param ent Entropy generated with the function.
             * @return Computed checksum (first ENT/32 bits of SHA-256).
             * @throw ForbiddenSize If length is not 12 or 24.
             */
            static uint8_t computeCheckSum(std::size_t length, const std::array<uint8_t, 32>& ent);

            /**
             * @brief Concatenate Entropy and CheckSum into a single buffer.
             * @param legnth Size of the mnemonic phrase (12 or 24).
             * @param ent Entropy generated with the function.
             * @param checksum Checksum computed with the function.
             * @return Buffer = ENT + CS as byte array.
             * @throw ForbiddenSize If length is not 12 or 24.
             */
            static std::array<uint8_t, 33> concatenateEntCs(std::size_t length, const std::array<uint8_t, 32>& ent, uint8_t checksum);

            /**
             * @brief Convert ENT+CS buffer into 11-bit word indices.
             * @param length Size of the mnemonic phrase (12 or 24).
             * @param buffer ENT + CS buffer.
             * @return Array of indices (0–2047).
             * @throw ForbiddenSize If length is not 12 or 24.
             */
            static std::array<uint16_t, 24> mapping(std::size_t length, const std::array<uint8_t, 33>& buffer);

            /**
             * @brief Convert mapping indices into mnemonic words.
             *
             * @param length Size of mnemonic phrase (12 or 24).
             * @param indices Array of 11-bit indices.
             * @param language Language code ("en", "fr", ...).
             * @return Vector containing the mnemonic words.
             * @throw ForbiddenSize If length is not 12 or 24.
             * @throw LanguageException If language is unsupported.
             */
            static std::vector<std::string> wordsFromMapping(std::size_t length, const std::array<uint16_t, 24>& indices, const std::string& language);

            /**
             * @brief Derive the 512-bit seed using PBKDF2-HMAC-SHA512.
             *
             * According to BIP-39 specification:
             * PBKDF2(
             *   password = mnemonic sentence (UTF-8),
             *   salt = "mnemonic" + passphrase,
             *   iterations = 2048,
             *   HMAC-SHA512
             * )
             *
             * This version uses secure_string for mnemonic and passphrase
             * to guarantee memory zeroization after usage.
             * 
             * @param mnemonicSentence Full mnemonic sentence (space-separated words).
             * @param passphrase Optional passphrase (empty string if none).
             *
             * @return Derived seed (512 bits / 64 bytes).
             *
             * @throw CryptoException If PBKDF2 derivation fails.
             */
            static Seed512 computeSeedPBKDF2(const secure_string& mnemonicSentence, const secure_string& passphrase = "");


    };
}


#endif

