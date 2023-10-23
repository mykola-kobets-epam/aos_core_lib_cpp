/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CERTMODULE_HPP_
#define AOS_CERTMODULE_HPP_

#include "aos/common/crypto.hpp"
#include "aos/common/tools/array.hpp"
#include "aos/common/tools/enum.hpp"
#include "aos/common/tools/string.hpp"
#include "aos/iam/config.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/**
 * Module key usage name length.
 */
constexpr auto cModuleKeyUsageNameLen = AOS_CONFIG_CERTMODULE_KEY_USAGE_LEN;

/**
 * Maximum number of module key usages.
 */
constexpr auto cModuleKeyUsagesMaxCount = AOS_CONFIG_CERTMODULE_KEY_USAGE_MAX_COUNT;

/**
 * Certificate type name length.
 */
constexpr auto cCertificateTypeLen = AOS_CONFIG_CERTMODULE_CERT_TYPE_NAME_LEN;

/**
 * Max number of invalid certificates per module.
 */
constexpr auto cInvalidCertsPerModule = AOS_CONFIG_CERTHANDLER_INVALID_CERT_PER_MODULE;

/**
 * Max number of invalid keys per module.
 */
constexpr auto cInvalidKeysPerModule = AOS_CONFIG_CERTHANDLER_INVALID_KEYS_PER_MODULE;

/**
 * Max number of IAM certificates per module.
 */
constexpr auto cCertsPerModule = AOS_CONFIG_CERTHANDLER_MAX_CERTS_PER_MODULE;

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
 * Extended key usage type.
 */
class ExtendedKeyUsageType {
public:
    enum class Enum { eClientAuth, eServerAuth };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sContentTypeStrings[] = {"clientAuth", "serverAuth"};
        return Array<const char* const>(sContentTypeStrings, ArraySize(sContentTypeStrings));
    };
};

using ExtendedKeyUsageEnum = ExtendedKeyUsageType::Enum;
using ExtendedKeyUsage = EnumStringer<ExtendedKeyUsageType>;

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
    unsigned mMaxCertificates = 0U;
    /**
     * Extra extensions needed for CSR. Current supported values: [clientAuth, serverAuth]
     */
    StaticArray<ExtendedKeyUsage, cModuleKeyUsagesMaxCount> mExtendedKeyUsage;
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
 * General certificate information.
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
    /**
     * Compares certificate info.
     *
     * @param certInfo info to compare.
     * @return bool.
     */
    bool operator==(const CertInfo& certInfo) const;
    /**
     * Compares certificate info.
     *
     * @param certInfo info to compare.
     * @return bool.
     */
    bool operator!=(const CertInfo& certInfo) const { return !operator==(certInfo); }
};

/**
 * Provides API to manage certificates of the same IAM certificate type.
 */
class CertModuleItf {
public:
    /**
     * Creates a new object instance.
     *
     * @param csrProvider a reference to x509 csr provider instance.
     */
    CertModuleItf(crypto::x509::CSRProviderItf& csrProvider);

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
     * Generates private key.
     *
     * @param password owner password.
     * @return RetWithError<crypto::PrivateKey*>.
     */
    virtual RetWithError<crypto::PrivateKey*> CreateKey(const String& password) = 0;

    /**
     * Applies certificate chain to a module.
     *
     * @param certChain certificate chain.
     * @param[out] topCertInfo info about a top certificate in a chain.
     * @param[out] password owner password.
     * @return Error.
     */
    virtual Error ApplyCertificateChain(
        const Array<crypto::x509::Certificate>& certChain, CertInfo& topCertInfo, String& password)
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
     * Creates certificate request.
     *
     * @param subject certificate subject.
     * @param privKey private key.
     * @param[out] csr result csr.
     * @return Error.
     */
    Error CreateCSR(const String& subject, const crypto::PrivateKey& privKey, crypto::x509::CSR& csr);

    /**
     * Returns IAM module certificate type.
     *
     * @return const String&.
     */
    const String& GetCertType() const;

    /**
     * Returns module configuration.
     *
     * @return const ModuleConfig&.
     */
    const ModuleConfig& GetModuleConfig() const;

    /**
     * Returns valid module certificates.
     *
     * @return const Array<CertInfo>&.
     */
    const Array<CertInfo>& GetValidCerts() const;

    /**
     * Removes invalid certificates.
     *
     * @param password owner password.
     * @return Error.
     */
    Error RemoveInvalidCerts(const String& password);

    /**
     * Removes invalid keys.
     *
     * @param password owner password.
     * @return Error.
     */
    Error RemoveInvalidKeys(const String& password);

    /**
     * Destroys certificate module interface.
     */
    virtual ~CertModuleItf() = default;

protected:
    /**
     * Validates certificates in a module and returns information about valid/invalid certificates.
     *
     * @param[out] validInfo information about valid certificates.
     * @param[out] invalidCerts invalid certificate URLs.
     * @param[out] invalidKeys URLs of invalid certificate keys.
     * @return Error.
     TODO:It is expected now that module sets its valid/invalid info in the constructor. clarify whether this method
    needed. virtual Error ValidateCertificates(Array<CertInfo>& validInfo, Array<StaticString<cURLLen>>& invalidCerts,
        Array<StaticString<cURLLen>>& invalidKeys)
        = 0;
    */

    /**
     * Valid certificates.
     */
    StaticArray<CertInfo, cCertsPerModule> mValidCerts;

    /**
     * Invalid certificates.
     */
    StaticArray<StaticString<cURLLen>, cInvalidCertsPerModule> mInvalidCerts;
    /**
     * Invalid keys.
     */
    StaticArray<StaticString<cURLLen>, cInvalidKeysPerModule> mInvalidKeys;

    /**
     * Certificate type, served by a module.
     */
    StaticString<cCertificateTypeLen> mCertType;

    /**
     * Module configuration.
     */
    ModuleConfig mModuleConfig;

    /**
     * CSR provider.
     */
    crypto::x509::CSRProviderItf& mCsrProvider;
};

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
