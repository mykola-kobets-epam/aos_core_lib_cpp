/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CERTMODULE_HPP_
#define AOS_CERTMODULE_HPP_

#include "aos/common/tools/array.hpp"
#include "aos/common/tools/enum.hpp"
#include "aos/common/tools/string.hpp"
#include "aos/iam/config.hpp"

namespace aos {
namespace iam {

/**
 * Module key usage name length.
 */
constexpr auto cModuleKeyUsageNameLen = AOS_IAM_TYPES_MODULE_KEY_USAGE_LEN;

/**
 * Maximum number of module key usages.
 */
constexpr auto cModuleKeyUsagesMaxCount = AOS_IAM_TYPES_MODULE_KEY_USAGE_MAX_COUNT;

/**
 * Certificate type name length.
 */
constexpr auto cCertificateTypeLen = AOS_IAM_CERTIFICATE_TYPE_NAME_LEN;

/**
 * Public/private keys generating algorithm
 */
class KeyGenAlgorithmType {
public:
    enum class Enum { eRSA };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sContentTypeStrings[] = {"RSA"};
        return Array<const char* const>(sContentTypeStrings, ArraySize(sContentTypeStrings));
    };
};

using KeyGenAlgorithmEnum = KeyGenAlgorithmType::Enum;
using KeyGenAlgorithm = EnumStringer<KeyGenAlgorithmType>;

/**
 * ModuleConfig module configuration.
 */
struct ModuleConfig {
    /**
     * Key generating algorithm.
     */
    KeyGenAlgorithm mKeyGenAlgorithm;
    /**
     * Maximum number of certificates for module.
     */
    int mMaxCertificates = 0;
    /**
     * Extra extensions needed for CSR. Current supported values: [clientAuth, serverAuth]
     */
    StaticArray<StaticString<cModuleKeyUsageNameLen>, cModuleKeyUsagesMaxCount> mExtendedKeyUsage;
    /**
     * Alternative DNS names.
     */
    StaticArray<StaticString<crypto::cDnsNameLen>, crypto::cAltDnsNamesCount> mAlternativeNames;
    /**
     * Skip certificate chain validation.
     */
    bool mSkipValidation = 0;
};

/**
 * General information information about certificate.
 */
struct CertInfo {
    /**
     * Certificate issuer name.
     */
    StaticString<crypto::cCertificateIssuerLen> mIssuer;
    /**
     * Certificate serial number.
     */
    StaticString<crypto::cCertificateSerialNumberLen> mSerial;
    /**
     * Certificate url.
     */
    StaticString<cURLLen> mCertURL;
    /**
     * Certificate's private key url.
     */
    StaticString<cURLLen> mKeyURL;
    /**
     * Certificate expiration time.
     */
    time::Time mNotAfter;
};

/**
 * Provides API to manage certificates of the same IAM certificate type.
 */
class CertModuleItf {
public:
    /**
     * Validates certificates in a module and returns information about valid/invalid certificates.
     *
     * @param[out] validInfo information about valid certificates.
     * @param[out] invalidCerts invalid certificate URLs.
     * @param[out] invalidKeys URLs of invalid certificate keys.
     * @return Error.
     */
    virtual Error ValidateCertificates(Array<CertInfo>& validInfo, Array<StaticString<cURLLen>>& invalidCerts,
        Array<StaticString<cURLLen>>& invalidKeys)
        = 0;

    /**
     * Owns the module.
     *
     * @param password certficate password.
     * @return Error.
     */
    virtual Error SetOwner(const String& password) = 0;

    /**
     * Removes all module certificates.
     *
     * @return Error.
     */
    virtual Error Clear() = 0;

    /**
     * Generates private key using given password and algorithm.
     *
     * @param algorithm key generating algorithm.
     * @param password owner password.
     * @return RetWithError<crypto::PrivateKey&>.
     */
    virtual RetWithError<crypto::PrivateKey&> CreateKey(KeyGenAlgorithm algorithm, const String& password) = 0;

    /**
     * Applies certificate chain to a module.
     *
     * @param certChain certificate chain.
     * @param[out] topCertInfo info about a top certificate in a chain.
     * @param[out] password password for a top certificate.
     * @return Error.
     */
    virtual Error ApplyCertificateChain(
        const Array<crypto::x509::Certificate*>& certChain, CertInfo& topCertInfo, String& password)
        = 0;

    /**
     * Removes certificate chain using top level certificate URL and password.
     *
     * @param certURL top level certificate URL.
     * @param password owner password.
     * @return Error.
     */
    virtual Error RemoveCertificateChain(const String& certURL, const String& password) = 0;

    /**
     * Removes private key from a module.
     *
     * @param keyURL private key URL.
     * @param password owner password.
     * @return Error.
     */

    virtual Error RemoveKey(const String& keyURL, const String& password) = 0;

    /**
     * Returns IAM module certificate type.
     *
     * @return const String&.
     */
    const String& getCertType() const;

    /**
     * Returns module configuration.
     *
     * @return const ModuleConfig&.
     */
    const ModuleConfig& getModuleConfig() const;

    /**
     * Destroys certificate module interface.
     */
    virtual ~CertModuleItf() = default;

protected:
    /**
     * Certificate type, served by a module.
     */
    StaticString<cCertificateTypeLen> mCertType;

    /**
     * Module configuration.
     */
    ModuleConfig mModuleConfig;
};

} // namespace iam
} // namespace aos

#endif
