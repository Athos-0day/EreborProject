/**
 * @file test_seed.cpp
 * @brief Unit tests for Erebor::Seed using Catch2 and official BIP-39 vectors.
 * @author Athos-0day
 * @date 2026
 *
 * This test suite verifies:
 * - Entropy generation
 * - Checksum computation
 * - Concatenation of ENT+CS
 * - Mapping to 11-bit indices
 * - Conversion to mnemonic words
 * - PBKDF2-HMAC-SHA512 seed derivation
 *
 * Uses official BIP-39 test vector:
 * https://bip39.dev/fr/
 */

#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"

#include "../include/secure_string.hpp"
#include "../include/seed.hpp"
#include <iomanip>
#include <sstream>

using namespace Erebor;

/**
 * @brief Helper to convert Seed512 to hex string
 */
static std::string hexString(const Seed::Seed512& seed) {
    std::ostringstream oss;
    for (auto b : seed) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

TEST_CASE("Seed::generateEntropy produces correct size", "[generateEntropy]") {
    auto ent12 = Seed::generateEntropy(12);
    REQUIRE(ent12.size() == 32); 

    auto ent24 = Seed::generateEntropy(24);
    REQUIRE(ent24.size() == 32); 

    REQUIRE_THROWS_AS(Seed::generateEntropy(15), ForbiddenSize);
}

TEST_CASE("Seed::computeCheckSum computes correct bits", "[computeCheckSum]") {
    std::array<uint8_t,32> ent{};
    ent[0] = 0xFF;

    uint8_t cs12 = Seed::computeCheckSum(12, ent);
    uint8_t cs24 = Seed::computeCheckSum(24, ent);

    REQUIRE(cs12 <= 0x0F); // 4 bits for 12-word checksum
    REQUIRE(cs24 <= 0xFF); // 8 bits for 24-word checksum

    REQUIRE_THROWS_AS(Seed::computeCheckSum(10, ent), ForbiddenSize);
}

TEST_CASE("Seed::concatenateEntCs combines entropy + checksum", "[concatenateEntCs]") {
    std::array<uint8_t,32> ent{};
    ent[0] = 0xAA;
    uint8_t cs = 0x0F;

    auto buffer12 = Seed::concatenateEntCs(12, ent, cs);
    REQUIRE(buffer12[0] == 0xAA);
    REQUIRE((buffer12[16] >> 4) == cs); // first 4 bits of checksum

    REQUIRE_THROWS_AS(Seed::concatenateEntCs(15, ent, cs), ForbiddenSize);
}

TEST_CASE("Seed::mapping correctly maps buffer to 11-bit indices", "[mapping]") {
    std::array<uint8_t,33> buffer{};
    buffer[0] = 0xFF;

    auto indices = Seed::mapping(24, buffer);
    REQUIRE(indices.size() == 24);

    for(auto idx : indices) {
        REQUIRE(idx <= 2047); // 11-bit indices
    }

    REQUIRE_THROWS_AS(Seed::mapping(15, buffer), ForbiddenSize);
}

TEST_CASE("Seed::wordsFromMapping returns correct number of words", "[wordsFromMapping]") {
    std::array<uint16_t,24> indices{};
    for(size_t i=0;i<24;++i) indices[i] = i;

    auto words = Seed::wordsFromMapping(24, indices, "en");
    REQUIRE(words.size() == 24);

    REQUIRE_THROWS_AS(Seed::wordsFromMapping(24, indices, "xx"), LanguageException);
}

/**
 * @brief Test PBKDF2 against official BIP-39 test vector
 *
 * Vector from https://bip39.dev/fr/
 * 12-word mnemonic, empty passphrase
 */
TEST_CASE("Seed::computeSeedPBKDF2 matches official BIP39 vector", "[computeSeedPBKDF2]") {
    // Official 12-word vector
    std::string mnemonic_str = "adjust cloth video dilemma magic news field either wisdom column park alter";
    std::string passphrase_str = "";

    secure_string mnemonic(mnemonic_str);
    secure_string pass(passphrase_str);

    auto seed = Seed::computeSeedPBKDF2(mnemonic, pass);

    // Expected seed in hex from official BIP-39
    std::string expected_seed_hex =
        "ed3ed876e9d3765e8d2c18023e004429e2cb71c355a655b4103eac53ac8ce20154e2980294e0a153ddefa2c197efc017e43b54c382a4ac17158b8c035aae1f0f";

    REQUIRE(hexString(seed).substr(0, expected_seed_hex.size()) == expected_seed_hex);
}
