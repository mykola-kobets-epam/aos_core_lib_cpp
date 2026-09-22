/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_IAM_CERTHANDLER_ITF_CERTHANDLER_HPP_
#define AOS_CORE_IAM_CERTHANDLER_ITF_CERTHANDLER_HPP_

#include <core/common/iamclient/itf/certprovider.hpp>
#include <core/common/tools/thread.hpp>
#include <core/iam/config.hpp>

namespace aos::iam::certhandler {

/** @addtogroup iam Identification and Access Manager
 *  @{
 */

/**
 * Max number of certificate modules.
 */
constexpr auto cIAMCertModulesMaxCount = AOS_CONFIG_CERTHANDLER_MODULES_MAX_COUNT;

/**
 * Maximum number of module key usages.
 */
constexpr auto cModuleKeyUsagesMaxCount = AOS_CONFIG_CERTHANDLER_KEY_USAGE_MAX_COUNT;

/**
 * Password max length.
 */
constexpr auto cPasswordLen = AOS_CONFIG_CERTHANDLER_PASSWORD_LEN;

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
using ExtendedKeyUsage     = EnumStringer<ExtendedKeyUsageType>;

/**
 * Certificate module type.
 *
 * - normal: CA-issued leaf cert/key pair (CSR / ApplyCert flow)
 * - selfSigned: module generates its own self-signed certificate
 * - root: trusted root CA certificates without private keys
 */
class CertModuleTypeType {
public:
    enum class Enum { eNormal, eSelfSigned, eRoot };

    static const Array<const char* const> GetStrings()
    {
        static const char* const sCertModuleTypeStrings[] = {"normal", "selfSigned", "root"};
        return Array<const char* const>(sCertModuleTypeStrings, ArraySize(sCertModuleTypeStrings));
    };
};

using CertModuleTypeEnum = CertModuleTypeType::Enum;
using CertModuleType     = EnumStringer<CertModuleTypeType>;

/**
 * Module configuration.
 */
struct ModuleConfig {
    /**
     * Key type.
     */
    crypto::KeyType mKeyType;
    /**
     * Maximum number of certificates for module.
     */
    size_t mMaxCertificates {};
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
    bool mSkipValidation {};
    /**
     * Certificate module type.
     */
    CertModuleType mCertType {};
};

/**
 * Certificate handler interface.
 */
class CertHandlerItf : public iamclient::CertProviderItf {
public:
    /**
     * Returns IAM cert types.
     *
     * @param[out] certTypes result certificate types.
     * @returns Error.
     */
    virtual Error GetCertTypes(Array<StaticString<cCertTypeLen>>& certTypes) const = 0;

    /**
     * Owns security storage.
     *
     * @param certType certificate type.
     * @param password owner password.
     * @returns Error.
     */
    virtual Error SetOwner(const String& certType, const String& password) = 0;

    /**
     * Clears security storage.
     *
     * @param certType certificate type.
     * @returns Error.
     */
    virtual Error Clear(const String& certType) = 0;

    /**
     * Creates key pair.
     *
     * @param certType certificate type.
     * @param subjectCommonName common name of the subject.
     * @param password owner password.
     * @param[out] pemCSR certificate signing request in PEM.
     * @returns Error.
     */
    virtual Error CreateKey(
        const String& certType, const String& subjectCommonName, const String& password, String& pemCSR)
        = 0;

    /**
     * Applies certificate.
     *
     * @param certType certificate type.
     * @param pemCert certificate in a pem format.
     * @param[out] info result certificate information.
     * @returns Error.
     */
    virtual Error ApplyCertificate(const String& certType, const String& pemCert, CertInfo& info) = 0;

    /**
     * Updates certificates for the module (replaces the whole set).
     *
     * @param certType certificate type.
     * @param pemCerts certificates in PEM format.
     * @param password owner password.
     * @param[out] resCerts result certificate information.
     * @returns Error.
     */
    virtual Error UpdateCerts(const String& certType, const Array<StaticString<crypto::cCertPEMLen>>& pemCerts,
        const String& password, Array<CertInfo>& resCerts)
        = 0;

    /**
     * Creates a self signed certificate.
     *
     * @param certType certificate type.
     * @param password owner password.
     * @returns Error.
     */
    virtual Error CreateSelfSignedCert(const String& certType, const String& password) = 0;

    /**
     * Returns module configuration.
     *
     * @param certType certificate type.
     * @returns RetWithError<ModuleConfig>.
     */
    virtual RetWithError<ModuleConfig> GetModuleConfig(const String& certType) const = 0;

    /**
     * Destroys certificate handler interface.
     */
    virtual ~CertHandlerItf() = default;
};

/** @}*/

} // namespace aos::iam::certhandler

#endif
