/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_COMMON_CRYPTO_ITF_CERTLOADER_HPP_
#define AOS_CORE_COMMON_CRYPTO_ITF_CERTLOADER_HPP_

#include "pkcs11url.hpp"
#include "x509.hpp"

namespace aos::crypto {

/**
 * Loads certificates and keys interface.
 */
class CertLoaderItf {
public:
    /**
     * Loads certificate chain by URL.
     *
     * @param url input url.
     * @return RetWithError<SharedPtr<crypto::x509::CertificateChain>>.
     */
    virtual RetWithError<SharedPtr<x509::CertificateChain>> LoadCertsChainByURL(const String& url) = 0;

    /**
     * Loads certificate URL chain by URL.
     *
     * @param url input url.
     * @return RetWithError<SharedPtr<StaticArray<StaticString<cURLLen>, cCertChainSize>>>.
     */
    virtual RetWithError<SharedPtr<StaticArray<StaticString<cURLLen>, cCertChainSize>>> LoadCertURLChainByURL(
        const String& url)
    {
        (void)url;

        return {nullptr, ErrorEnum::eNone};
    }

    /**
     * Loads private key by URL.
     *
     * @param url input url.
     * @return RetWithError<SharedPtr<crypto::PrivateKeyItf>>.
     */
    virtual RetWithError<SharedPtr<crypto::PrivateKeyItf>> LoadPrivKeyByURL(const String& url) = 0;

    /**
     * Destroys cert loader instance.
     */
    virtual ~CertLoaderItf() = default;
};

/**
 * Parses scheme part of URL.
 *
 * @param url input url.
 * @param[out] scheme url scheme.
 * @return Error.
 */
Error ParseURLScheme(const String& url, String& scheme);

/**
 * Parses URL with file scheme.
 *
 * @param url input url.
 * @param[out] path file path.
 * @return Error.
 */
Error ParseFileURL(const String& url, String& path);

/**
 * Encodes PKCS11 ID to percent-encoded string.
 *
 * @param id PKCS11 ID.
 * @param idStr percent-encoded string.
 * @return Error.
 */
Error EncodePKCS11ID(const Array<uint8_t>& id, String& idStr);

/**
 * Decodes PKCS11 ID from percent-encoded string.
 *
 * @param idStr percent-encoded string.
 * @param id PKCS11 ID.
 * @return Error.
 */
Error DecodeToPKCS11ID(const String& idStr, Array<uint8_t>& id);

/**
 * Parses url with PKCS11 scheme.
 *
 * @param url input url.
 * @param[out] library PKCS11 library.
 * @param[out] token token label.
 * @param[out] label certificate label.
 * @param[out] id certificate id.
 * @param[out] userPin user PIN.
 * @return Error.
 */
Error ParsePKCS11URL(
    const String& url, String& library, String& token, String& label, Array<uint8_t>& id, String& userPin);

/**
 * Builds PKCS11 URL.
 *
 * @param library PKCS11 library.
 * @param token token label.
 * @param label object label.
 * @param id object id.
 * @param userPin user PIN.
 * @param[out] url output URL.
 * @return Error.
 */
Error BuildPKCS11URL(const String& library, const String& token, const String& label, const Array<uint8_t>& id,
    const String& userPin, String& url);

} // namespace aos::crypto

#endif
