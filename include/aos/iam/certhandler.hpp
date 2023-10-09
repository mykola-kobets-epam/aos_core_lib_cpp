/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CERTHANDLER_HPP_
#define AOS_CERTHANDLER_HPP_

#include "aos/common/crypto.hpp"
#include "aos/common/time.hpp"
#include "aos/common/tools/array.hpp"
#include "aos/common/tools/error.hpp"
#include "aos/common/tools/function.hpp"
#include "aos/common/tools/log.hpp"
#include "aos/common/tools/string.hpp"
#include "aos/common/tools/thread.hpp"
#include "aos/common/tools/utils.hpp"
#include "aos/common/types.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/**
 * General information information about certificate.
 */
struct CertInfo {
    /**
     * Certificate issuer name.
     */
    StaticString<cCertificateIssuerLen> mIssuer;
    /**
     * Certificate serial number.
     */
    StaticString<cCertificateSerialNumberLen> mSerial;
    /**
     * Certificate url.
     */
    StaticString<cURLLen> mCertURL;
    /**
     * Certificate's public key url.
     */
    StaticString<cURLLen> mKeyURL;
    /**
     * Certificate expiration time.
     */
    time::Time mNotAfter;
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
     * Returns info for certificate with specified issuer name and serial number.
     *
     * @param issuer issuer name.
     * @param serial serial number.
     * @return RetWithError<CertInfo>.
     */
    virtual RetWithError<CertInfo> GetCertInfo(const String& issuer, const String& serial) = 0;

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
 * CertModule provides API to manage module certificates.
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
     * @param algorithm certificate generation algorithm.
     * @param password certificate password.
     *
     * @return RetWithError<crypto::PrivateKey&>.
     */
    virtual RetWithError<crypto::PrivateKey&> CreateKey(const String& algorithm, const String& password) = 0;

    /**
     * Applies certificate chain to a module.
     *
     * @param certChain certificate chain.
     * @param[out] topCertInfo info about a top certificate in a chain.
     * @param[out] password password for a top certificate.
     * @return Error.
     */
    virtual Error ApplyCertificateChain(
        const Array<crypto::x509::Certificate*>& certChain, CertInfo& topCertInfo, StaticString<cPasswordLen>& password)
        = 0;

    /**
     * Removes certificate chain using top level certificate URL and password.
     *
     * @param certURL top level certificate URL.
     * @param password certificate password.
     *
     * @return Error.
     */
    virtual Error RemoveCertificateChain(const String& certURL, const String& password) = 0;

    /**
     * Removes private key from a module.
     *
     * @param keyURL private key URL.
     * @param password certificate password.
     *
     * @return Error.
     */

    virtual Error RemoveKey(const String& keyURL, const String& password) = 0;

    /**
     * Destroys certificate module interface.
     */
    virtual ~CertModuleItf() = default;
};

/** @addtogroup iam Identification and Access Manager
 *  @{
 */

/**
 * Handles keys and certificates.
 */
class CertHandler {
public:
    /**
     * Registers module.
     *
     * @param module a reference to a module.
     * @returns void.
     */
    void RegisterModule(CertModuleItf& module);

    /**
     * Returns IAM cert types.
     *
     * @param[out] certTypes result certificate types.
     * @returns void.
     */
    void GetCertTypes(Array<StaticString<cCertificateTypeLen>>& certTypes);

    /**
     * Owns security storage.
     *
     * @param certTypes certificate type.
     * @param password certificate password.
     * @returns Error.
     */
    Error SetOwner(const String& certType, const String& password);

    /**
     * Clears security storage.
     *
     * @param certType certificate type.
     * @returns Error.
     */
    Error Clear(const String& certType);

    /**
     * Creates key pair.
     *
     * @param certType certificate type.
     * @param subject subject of CSR.
     * @param password certificate password.
     * @param[out] csr certificate signing request.
     * @returns Error.
     */
    Error CreateKey(const String& certType, const String& subject, const String& password, Array<uint8_t>& csr);

    /**
     * Applies certificate.
     *
     * @param certType certificate type.
     * @param cert certificate.
     * @returns RetWithError<CertInfo>.
     */
    RetWithError<CertInfo> ApplyCertificate(const String& certType, const Array<uint8_t>& cert);

    /**
     * Returns certificate info.
     *
     * @param certType certificate type.
     * @param issuer issuer name.
     * @param serial serial number.
     * @returns RetWithError<CertInfo>.
     */
    RetWithError<CertInfo> GetCertificate(const String& certType, const Array<uint8_t>& issuer, const String& serial);

    /**
     * Creates a self signed certificate.
     *
     * @param certType certificate type.
     * @param password certificate password.
     * @returns Error.
     */
    Error CreateSelfSignedCert(const String& certType, const String& password);

    /**
     * Destroys handler.
     */
    ~CertHandler() = default;
};

/** @}*/

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
