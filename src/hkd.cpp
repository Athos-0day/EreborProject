#include "../include/hkd.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <secp256k1.h>

#include <cstring>
#include <sstream>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <stdexcept>

/**
 * @file hkd.cpp
 * @brief Implementation of the HKD class compliant with BIP-32.
 * @author Erebor Project
 * @date 2026
 */

namespace Erebor {

    HKD::ExtendedKey HKD::computeMasterNode(const uint8_t* seed, size_t len) {
        // BIP-32 defined salt
        const std::string salt = "Bitcoin seed";
        std::array<uint8_t, 64> I;
        unsigned int I_len = 0;

        // HMAC-SHA512(Key="Bitcoin seed", Data=seed)
        if (HMAC(EVP_sha512(), salt.c_str(), static_cast<int>(salt.size()), 
                 seed, len, I.data(), &I_len) == nullptr) {
            throw CryptoException("HMAC-SHA512 Master Node generation failed");
        }

        ExtendedKey master;
        // Left 32 bytes: master private key / Right 32 bytes: master chain code
        std::copy(I.begin(), I.begin() + 32, master.key.begin());
        std::copy(I.begin() + 32, I.end(), master.chainCode.begin());

        // Clean up sensitive intermediate data
        secure_memzero(I.data(), I.size());

        return master;
    }

    std::array<uint8_t, 33> HKD::computePublicKey(const std::array<uint8_t, 32>& privKey) {
        static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pubkey;
        std::array<uint8_t, 33> output;
        size_t outputLen = 33;

        if (!secp256k1_ec_seckey_verify(ctx, privKey.data())) {
            throw CryptoException("Invalid private key");
        }

        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data())) {
            throw CryptoException("Failure to create the public key");
        }

        secp256k1_ec_pubkey_serialize(ctx, output.data(), &outputLen, &pubkey, SECP256K1_EC_COMPRESSED);

        return output;
    }

    HKD::ExtendedKey HKD::deriveChildKey(const HKD::ExtendedKey& parent, uint32_t index) {
        std::vector<uint8_t> data;
        data.reserve(37); // 0x00 + masterKey + index = 37 if hardened

        if (isHardened(index)) {
            // Hardened derivation
            // Format: 0x00 | parent private key | index
            data.push_back(0x00);
            data.insert(data.end(), parent.key.begin(), parent.key.end());
        } else {
            // Classic derivation
            // Format: parent public key | index 
            std::array<uint8_t, 33> pubKey = computePublicKey(parent.key); 
            data.insert(data.end(), pubKey.begin(), pubKey.end());
        }

        // We add the index in BIG ENDIAN
        data.push_back(static_cast<uint8_t>((index >> 24) & 0xFF));
        data.push_back(static_cast<uint8_t>((index >> 16) & 0xFF));
        data.push_back(static_cast<uint8_t>((index >> 8) & 0xFF));
        data.push_back(static_cast<uint8_t>(index & 0xFF));

        // HMAC-SHA512 calculation
        std::array<uint8_t, 64> I;
        unsigned int I_len = 0;
        if (HMAC(EVP_sha512(), 
                parent.chainCode.data(), parent.chainCode.size(), 
                data.data(), data.size(), 
                I.data(), &I_len) == nullptr) {
            secure_memzero(data.data(), data.size());
            throw CryptoException("HMAC-SHA512 derivation failed");
        }
        
        // Clean the temporary buffer
        secure_memzero(data.data(), data.size());

        HKD::ExtendedKey child;
        
        // Child Chain Code = IR (right 32 bytes of I)
        std::copy(I.begin() + 32, I.end(), child.chainCode.begin());

        // Child Private Key = (IL + Parent Private Key) % n
        // We start by copying the parent key into the child key
        std::copy(parent.key.begin(), parent.key.end(), child.key.begin());

        static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        
        // This function adds I_L (the first 32 bytes of I, acting as a tweak) to child.key
        // It automatically handles the modulo over the secp256k1 curve order.
        if (!secp256k1_ec_seckey_tweak_add(ctx, child.key.data(), I.data())) {
            secure_memzero(I.data(), I.size());
            throw CryptoException("Invalid derived child key");
        }

        // Clean the I entropy
        secure_memzero(I.data(), I.size());

        return child;
    }

    HKD::ExtendedKey HKD::derivePath(const ExtendedKey& master, const std::string& path) {
        HKD::ExtendedKey currentKey = master;
        
        if (path.empty()) return currentKey;

        std::stringstream ss(path);
        std::string token;
        
        // Parse the path string separated by '/'
        while (std::getline(ss, token, '/')) {
            if (token == "m" || token == "M") continue; // Skip master notation
            if (token.empty()) continue;

            uint32_t index = 0;
            bool hardened = false;

            // Check for hardened marker (' or h)
            if (token.back() == '\'' || token.back() == 'h' || token.back() == 'H') {
                hardened = true;
                token.pop_back(); // Remove the marker
            }

            try {
                index = static_cast<uint32_t>(std::stoul(token));
            } catch (...) {
                throw std::invalid_argument("Invalid path format: " + path);
            }

            if (hardened) {
                index |= HARDENED_OFFSET;
            }

            ExtendedKey nextKey = deriveChildKey(currentKey, index);
            
            // Secure memory management: if the current key isn't the master, zeroize it
            // before overwriting to prevent intermediate keys from lingering in RAM.
            if (currentKey.key != master.key) {
                currentKey.zeroize();
            }
            
            currentKey = nextKey;
        }

        return currentKey;
    }

} // Namespace Erebor