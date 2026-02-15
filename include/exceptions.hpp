#ifndef EXCEPTIONS_HPP
#define EXCEPTIONS_HPP

#include <stdexcept>
#include <string>

/**
 * @file exceptions.hpp
 * @brief Custom exception hierarchy for cryptographic operations.
 * @author Athos-0day
 * @date 2026
 */

/**
 * @class CryptoException
 * @brief Base class for all cryptographic related exceptions.
 *
 * This class extends std::runtime_error and serves as the root
 * of the crypto exception hierarchy.
 *
 * Catch this type if you want to handle all crypto-related errors.
 */
class CryptoException : public std::runtime_error
{
public:
    /**
     * @brief Construct a new CryptoException.
     * @param message Error message.
     */
    using std::runtime_error::runtime_error;
};

/**
 * @class ForbiddenSize
 * @brief Thrown when an invalid mnemonic size is provided.
 *
 * This exception is raised when the mnemonic word count
 * does not match BIP-39 allowed values (12 or 24).
 *
 * @note Inherits from CryptoException.
 */
class ForbiddenSize : public CryptoException
{
public:
    /**
     * @brief Construct a new ForbiddenSize exception.
     * @param message Error description.
     */
    using CryptoException::CryptoException;
};

/**
 * @class LanguageException
 * @brief thrown when an invalid language is provided.
 * 
 * @note Inherits from CryptoException.
 */
class LanguageException : public CryptoException
{
public:
    /**
     * @brief Construct a new LanguageException exception.
     * @param message Error description.
     */
    using CryptoException::CryptoException;
};

#endif // EXCEPTIONS_HPP
