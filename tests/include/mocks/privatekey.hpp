/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_IAM_MOCKS_PRIVATEKEY_HPP_
#define AOS_IAM_MOCKS_PRIVATEKEY_HPP_

#include "aos/common/crypto.hpp"

namespace aos {
namespace crypto {

/**
 * RSA private key.
 */
class PrivateKeyMock : public PrivateKeyItf {
public:
    /**
     * Constructs object instance.
     *
     * @param pubKey public key component of a private key.
     */
    PrivateKeyMock(const RSAPublicKey& pubKey)
        : mPubKey(pubKey)
    {
    }

    /**
     * Returns public part of a private key.
     *
     * @return const PublicKeyItf&.
     */
    const PublicKeyItf& GetPublic() const override { return mPubKey; }

    /**
     * Calculates a signature of a given digest.
     *
     * @param digest input hash digest.
     * @param options signing options.
     * @param[out] signature result signature.
     * @return Error.
     */
    Error Sign(const Array<uint8_t>& digest, const SignOptions& options, Array<uint8_t>& signature) override
    {
        (void)digest;
        (void)options;
        (void)signature;

        return ErrorEnum::eFailed;
    }

    /**
     * Decrypts a cipher.
     *
     * @param cipher encrypted message.
     * @param[out] result decoded message.
     * @return Error.
     */
    Error Decrypt(const Array<uint8_t>& cipher, Array<uint8_t>& result) override
    {
        (void)cipher;
        (void)result;

        return ErrorEnum::eFailed;
    }

private:
    RSAPublicKey mPubKey;
};

} // namespace crypto
} // namespace aos

#endif
