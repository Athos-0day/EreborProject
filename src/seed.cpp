#include "../include/seed.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <cstring>
#include <sstream>
#include <fstream>
#include <mutex>
#include <unordered_map>

/**
 * @file seed.cpp
 * @brief Implementation of the Seed class compliant with BIP-39.
 * @author Athos-0day
 * @date 2026
 */

namespace Erebor {

    namespace {

        /**
         * @brief Check if the length of the mnemotic is a correct value
         * according to our restrictions.
         * @param length Size of the mnemonic.
         * @throw ForbidenSize If the size is not correct.
         */
        inline void checkLength(size_t length) {
            if ((length != 12) && (length != 24)) {
                throw ForbiddenSize("Mnemonic length must be 12 or 24 words.");
            }
        }

        /**
         * @brief Give the size of the ENT according to length.
         * 
         * @param length Size of the mnemonic.
         * @return std::size_t Size of the Entropy.
         */
        inline std::size_t entropyBytes(std::size_t length) {
            return (length == 12) ? 16 : 32; // 128 bits or 256 bits
        }

        /**
         * @brief Give the size of the Checksum according to length.
         * 
         * @param length Size of the mnemonic.
         * @return std::size_t Size of the CheckSum.
         */
        inline std::size_t checksumBits(std::size_t length) {
            return (length == 12) ? 4 : 8;
        }

        /**
         * @brief Load a BIP-39 wordlists.
         * 
         * @param path Path of the wordlist.
         * @return std::vector<std::string> The wordlist loaded.
         * @throw LanguageExceptionIf the file doesn't exist.
         */
        std::vector<std::string> loadWordListFromFile(const std::string& path) {
            std::ifstream file(path);
            if (!file)
                throw LanguageException("Unable to open wordlist file: " + path);

            std::vector<std::string> words;
            words.reserve(2048);

            std::string line;
            while (std::getline(file, line)) {

                // remove potential '\r'
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                if (!line.empty())
                    words.push_back(line);
            }

            if (words.size() != 2048)
                throw LanguageException("Invalid BIP-39 wordlist size in file: " + path);

            return words;
        }

        /**
         * @brief Get the Word List object.
         * 
         * @param language The language provided.
         * @return const std::vector<std::string>& The wordlist.
         * @throw LanguageException If the language is not supported.
         */
        const std::vector<std::string>& getWordList(const std::string& language) {

            static std::unordered_map<std::string, std::vector<std::string>> cache;
            static std::mutex mutex;

            std::lock_guard<std::mutex> lock(mutex);

            auto it = cache.find(language);
            if (it != cache.end())
                return it->second;

            std::string path;

            if (language == "en")
                path = "../wordlists/english.txt";
            else if (language == "fr")
                path = "../wordlists/french.txt";
            else
                throw LanguageException("Unsupported language: " + language);

            auto wordlist = loadWordListFromFile(path);

            auto inserted = cache.emplace(language, std::move(wordlist));
            return inserted.first->second;
        }
    }

    std::array<uint8_t, 32> Seed::generateEntropy(std::size_t length) {
        //Check the length
        checkLength(length);

        std::array<uint8_t, 32> entropy{};
        std::size_t bytes = entropyBytes(length);

        if (RAND_bytes(entropy.data(), static_cast<int>(bytes)) != 1)
            throw CryptoException("CSPRNG entropy generation failed.");

        return entropy;
    }

    uint8_t Seed::computeCheckSum(std::size_t length, const std::array<uint8_t, 32>& ent) {
        //Check the length
        checkLength(length);

        uint8_t hash[SHA256_DIGEST_LENGTH];
        std::size_t bytes = entropyBytes(length);

        //Compute the SHA256 of the entropy
        SHA256(ent.data(), bytes, hash);

        std::size_t csBits = checksumBits(length);

        return static_cast<uint8_t>(hash[0] >> (8 - csBits));
    }

    std::array<uint8_t, 33> Seed::concatenateEntCs(std::size_t length, const std::array<uint8_t, 32>& ent, uint8_t checksum) {
        //Check the length 
        checkLength(length);

        std::array<uint8_t, 33> buffer{};
        std::size_t bytes = entropyBytes(length);
        std::size_t csBits = checksumBits(length);

        std::memcpy(buffer.data(), ent.data(), bytes);

        buffer[bytes] = checksum << (8 - csBits);

        return buffer;
    }

    std::array<uint16_t, 24> Seed::mapping(std::size_t length, const std::array<uint8_t, 33>& buffer) {
        //Check the length 
        checkLength(length);

        std::array<uint16_t, 24> indices{};
        std::size_t totalBits = length * 11;
        std::size_t totalBytes = (totalBits + 7) / 8;

        uint32_t accumulator = 0;
        int bitsInAccumulator = 0;

        std::size_t wordIndex = 0;

        for (std::size_t i = 0; i < totalBytes; ++i) {
            accumulator = (accumulator << 8) | buffer[i];
            bitsInAccumulator += 8;

            while (bitsInAccumulator >= 11 && wordIndex < length) {
                bitsInAccumulator -= 11;

                indices[wordIndex++] =
                    static_cast<uint16_t>(
                        (accumulator >> bitsInAccumulator) & 0x7FF
                    );
            }
        }

        return indices;
    }

    std::vector<std::string> Seed::wordsFromMapping(std::size_t length, const std::array<uint16_t, 24>& indices, const std::string& language) {
        //Check the length
        checkLength(length);

        //Retrieve the wordlist
        const auto& wordlist = getWordList(language);

        //Creation of the vector of words
        std::vector<std::string> words;
        words.reserve(length);

        //Store each word in the vector
        //A value in indice is an index in the wordlist
        for (std::size_t i = 0; i < length; ++i) {
            if (indices[i] >= 2048)
                throw CryptoException("Invalid word index.");

            words.push_back(wordlist[indices[i]]);
        }

        return words;
    }

    Seed::Seed512 Seed::computeSeedPBKDF2(const secure_string& mnemonicSentence, const secure_string& passphrase) {
        Seed512 seed{};

        std::string salt = "mnemonic";
        salt += std::string(passphrase.data(), passphrase.size());

        if (PKCS5_PBKDF2_HMAC(
                mnemonicSentence.data(),                       
                static_cast<int>(mnemonicSentence.size()),
                reinterpret_cast<const unsigned char*>(salt.data()), 
                static_cast<int>(salt.size()),
                2048,
                EVP_sha512(),
                seed.size(),
                seed.data()
            ) != 1)
        {
            throw CryptoException("PBKDF2-HMAC-SHA512 derivation failed");
        }

        return seed;
    }
}