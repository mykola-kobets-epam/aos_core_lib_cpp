/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CERTMODULE_HPP_
#define AOS_CERTMODULE_HPP_

#include "aos/common/crypto.hpp"
#include "aos/common/time.hpp"
#include "aos/common/tools/allocator.hpp"
#include "aos/common/tools/array.hpp"
#include "aos/common/tools/enum.hpp"
#include "aos/common/tools/string.hpp"
#include "aos/common/tools/utils.hpp"
#include "aos/iam/config.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/**
 * Maximum number of module key usages.
 */
constexpr auto cModuleKeyUsagesMaxCount = AOS_CONFIG_CERTHANDLER_KEY_USAGE_MAX_COUNT;

/**
 * Certificate type name length.
 */
constexpr auto cCertTypeLen = AOS_CONFIG_CERTHANDLER_CERT_TYPE_NAME_LEN;

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
 * Module configuration.
 */
struct ModuleConfig {
    /**
     * Key generating algorithm.
     */
    KeyGenAlgorithm mKeyGenAlgorithm;
    /**
     * Maximum number of certificates for module.
     */
    size_t mMaxCertificates;
    /**
     * Extra extensions needed for CSR. Current supported values: [clientAuth, serverAuth]
     */
    StaticArray<ExtendedKeyUsage, cModuleKeyUsagesMaxCount> mExtendedKeyUsage;
    /**
     * Alternative DNS names.
     */
    StaticArray<StaticString<crypto::cDNSNameLen>, crypto::cAltDNSNamesCount> mAlternativeNames;
    /**
     * Skip certificate chain validation.
     */
    bool mSkipValidation;
};

/**
 * General certificate information.
 */
struct CertInfo {
    /**
     * Certificate issuer.
     */
    StaticArray<uint8_t, crypto::cCertIssuerSize> mIssuer;
    /**
     * Certificate serial number.
     */
    StaticArray<uint8_t, crypto::cCertSerialNumberSize> mSerial;
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
     * Checks whether certificate info is equal the the current one.
     *
     * @param certInfo info to compare.
     * @return bool.
     */
    bool operator==(const CertInfo& certInfo) const
    {
        return certInfo.mCertURL == mCertURL && certInfo.mIssuer == mIssuer && certInfo.mKeyURL == mKeyURL
            && certInfo.mNotAfter == mNotAfter && certInfo.mSerial == mSerial;
    }
    /**
     * Checks whether certificate info is equal the the current one.
     *
     * @param certInfo info to compare.
     * @return bool.
     */
    bool operator!=(const CertInfo& certInfo) const { return !operator==(certInfo); }

    /**
     * Prints object to log.
     *
     * @param log log to output.
     * @param certInfo object instance.
     * @return Log&.
     */
    friend Log& operator<<(Log& log, const CertInfo& certInfo)
    {
        log << "{certURL=" << certInfo.mCertURL << ", keyURL=" << certInfo.mKeyURL
            << ", notAfter=" << certInfo.mNotAfter << "}";
        return log;
    }
};

/**
 * Platform dependent secure certificate storage.
 */
class HSMItf {
public:
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
     * @return RetWithError<const crypto::PrivateKey*>.
     */
    virtual RetWithError<crypto::PrivateKey*> CreateKey(const String& password, KeyGenAlgorithm algorithm) = 0;

    /**
     * Applies certificate chain to a module.
     *
     * @param certChain certificate chain.
     * @param[out] certInfo info about a top certificate in a chain.
     * @param[out] password owner password.
     * @return Error.
     */
    virtual Error ApplyCert(const Array<crypto::x509::Certificate>& certChain, CertInfo& certInfo, String& password)
        = 0;

    /**
     * Removes certificate chain using top level certificate URL and password.
     *
     * @param certURL top level certificate URL.
     * @param password owner password.
     * @return Error.
     */
    virtual Error RemoveCert(const String& certURL, const String& password) = 0;

    /**
     * Removes private key from a module.
     *
     * @param keyURL private key URL.
     * @param password owner password.
     * @return Error.
     */

    virtual Error RemoveKey(const String& keyURL, const String& password) = 0;

    /**
     * Returns list of valid pairs, invalid certificates and invalid keys.
     *
     * @param[out] invalidCerts invalid certificate URLs.
     * @param[out] invalidKeys invalid key URLs.
     * @param[out] validCerts information about valid certificates.
     * @return Error.
     **/
    virtual Error ValidateCertificates(Array<StaticString<cURLLen>>& invalidCerts,
        Array<StaticString<cURLLen>>& invalidKeys, Array<CertInfo>& validCerts)
        = 0;
    /**
     * Destroys object instance.
     */
    virtual ~HSMItf() = default;
};

/**
 * StorageItf provides API to store/retrieve certificates info.
 */
class StorageItf {
public:
    /**
     * Adds new certificate info to the storage.
     *
     * @param certType certificate type.
     * @param certInfo certificate information.
     * @return Error.
     */
    virtual Error AddCertInfo(const String& certType, const CertInfo& certInfo) = 0;

    /**
     * Returns information about certificate with specified issuer and serial number.
     *
     * @param issuer certificate issuer.
     * @param serial serial number.
     * @param cert result certificate.
     * @return Error.
     */
    virtual Error GetCertInfo(const Array<uint8_t>& issuer, const Array<uint8_t>& serial, CertInfo& cert) = 0;

    /**
     * Returns info for all certificates with specified certificate type.
     *
     * @param certType certificate type.
     * @param[out] certsInfo result certificates info.
     * @return Error.
     */
    virtual Error GetCertsInfo(const String& certType, Array<CertInfo>& certsInfo) = 0;

    /**
     * Removes certificate with specified certificate type and url.
     *
     * @param certType certificate type.
     * @param certURL certificate URL.
     * @return Error.
     */
    virtual Error RemoveCertInfo(const String& certType, const String& certURL) = 0;

    /**
     * Removes all certificates with specified certificate type.
     *
     * @param certType certificate type.
     * @return Error.
     */
    virtual Error RemoveAllCertsInfo(const String& certType) = 0;

    /**
     * Destroys certificate info storage.
     */
    virtual ~StorageItf() = default;
};

/**
 * Provides API to manage certificates of the same IAM certificate type.
 */
class CertModule {
public:
    /**
     * Creates a new object instance.
     *
     * @param certType certificate type.
     * @param config module config.
     */
    CertModule(const String& certType, const ModuleConfig& config);

    /**
     * Initializes certificate module.
     *
     * @param x509Provider provider of x509 certificates, csr, keys.
     * @param hsm a reference to hardware security module.
     * @param storage a reference to certificate storage.
     * @return Error.
     */
    Error Init(crypto::x509::ProviderItf& x509Provider, HSMItf& hsm, StorageItf& storage);

    /**
     * Returns IAM module certificate type.
     *
     * @return const String&.
     */
    const String& GetCertType() const;

    /**
     * Returns information about certificate with specified issuer and serial number.
     *
     * @param issuer certificate issuer.
     * @param serial serial number.
     * @param resCert result certificate.
     * @return Error.
     */
    Error GetCertificate(const Array<uint8_t>& issuer, const Array<uint8_t>& serial, CertInfo& resCert);

    /**
     * Owns the module.
     *
     * @param password certficate password.
     * @return Error.
     */
    Error SetOwner(const String& password);

    /**
     * Removes all module certificates.
     *
     * @return Error.
     */
    Error Clear();

    /**
     * Generates private key.
     *
     * @param password owner password.
     * @return RetWithError<crypto::PrivateKey*> .
     */
    RetWithError<crypto::PrivateKey*> CreateKey(const String& password);

    /**
     * Creates certificate request.
     *
     * @param subject certificate subject.
     * @param privKey private key.
     * @param[out] pemCSR result csr in PEM.
     * @return Error.
     */
    Error CreateCSR(const Array<uint8_t>& subject, const crypto::PrivateKey& privKey, Array<uint8_t>& pemCSR);

    /**
     * Applies certificate to a module.
     *
     * @param pemCert certificate chain in PEM format.
     * @param[out] info result certificate information.
     * @returns Error.
     */
    Error ApplyCert(const Array<uint8_t>& pemCert, CertInfo& info);

    /**
     * Creates a self signed certificate.
     *
     * @param password owner password.
     * @returns Error.
     */
    Error CreateSelfSignedCert(const String& password);

private:
    static constexpr auto cCertChainSize = AOS_CONFIG_CERTHANDLER_CERTS_CHAIN_SIZE;
    static constexpr auto cPasswordLen = AOS_CONFIG_CERTHANDLER_PASSWORD_LEN;
    static constexpr auto cDNStringLen = AOS_CONFIG_CERTHANDLER_DN_STRING_LEN;
    static constexpr auto cValidSelfSignedCertPeriod = time::Years(100);

    static constexpr auto cOidExtensionExtendedKeyUsage = "2.5.29.37";
    static constexpr auto cOidExtKeyUsageClientAuth = "1.3.6.1.5.5.7.3.1";
    static constexpr auto cOidExtKeyUsageServerAuth = "1.3.6.1.5.5.7.3.2";

    using ModuleCertificates = StaticArray<CertInfo, cCertsPerModule>;
    using CertificateChain = StaticArray<crypto::x509::Certificate, cCertChainSize>;
    using SelfSignedCertificate = StaticArray<uint8_t, crypto::cPEMCertSize>;

    Error RemoveInvalidCerts(const String& password);
    Error RemoveInvalidKeys(const String& password);
    Error TrimCerts(const String& password);
    Error CheckCertChain(const Array<crypto::x509::Certificate>& chain);
    Error SyncValidCerts(const Array<CertInfo>& validCert);

    crypto::x509::ProviderItf* mX509Provider;
    HSMItf*                    mHSM;
    StorageItf*                mStorage;

    StaticString<cCertTypeLen> mCertType;
    ModuleConfig               mModuleConfig;

    StaticArray<StaticString<cURLLen>, cCertsPerModule> mInvalidCerts, mInvalidKeys;

    StaticAllocator<Max(2U * sizeof(ModuleCertificates),
        sizeof(SelfSignedCertificate) + sizeof(CertificateChain) + sizeof(ModuleCertificates))>
        mAllocator;
};

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
