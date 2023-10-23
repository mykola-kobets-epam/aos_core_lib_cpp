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
#include "aos/iam/certmodule.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/**
 * Max number of certificate modules.
 */
constexpr auto cIAMCertModulesMaxCount = AOS_CONFIG_CERTHANDLER_MODULES_MAX_COUNT;

/** @addtogroup iam Identification and Access Manager
 *  @{
 */

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
 * Handles keys and certificates.
 */
class CertHandler {
public:
    /**
     * Creates a new object instance.
     *
     * @param storage a reference to a storage interface.
     * @param certProvider a reference to x509 certificate provider instance.
     */
    CertHandler(StorageItf& storage, crypto::x509::CertificateProviderItf& certProvider);

    /**
     * Registers module.
     *
     * @param module a reference to a module.
     * @returns Error.
     */
    Error RegisterModule(CertModuleItf& module);

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
     * @param certType certificate type.
     * @param password owner password.
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
     * @param password owner password.
     * @param[out] csr certificate signing request.
     * @returns Error.
     */
    Error CreateKey(const String& certType, const String& subject, const String& password, crypto::x509::CSR& csr);

    /**
     * Applies certificate.
     *
     * @param certType certificate type.
     * @param pemCert certificate in a pem format.
     * @param[out] info result certificate information.
     * @returns Error.
     */
    Error ApplyCertificate(const String& certType, const Array<uint8_t>& pemCert, CertInfo& info);

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
     * @param password owner password.
     * @returns Error.
     */
    Error CreateSelfSignedCert(const String& certType, const String& password);

    /**
     * Destroys certificate handler object instance.
     */
    ~CertHandler();

private:
    static constexpr auto cCertChainSize = AOS_CONFIG_CERTHANDLER_CERTS_CHAIN_SIZE;
    static constexpr auto cMaxSelfSignedCertSize = AOS_CONFIG_CERTHANDLER_PEM_SELFSIGNED_CERT_SIZE;
    static constexpr auto cPasswordLen = AOS_CONFIG_CERTHANDLER_PASSWORD_LEN;

    CertModuleItf*                    FindModule(const String& certType);
    RetWithError<crypto::PrivateKey*> CreatePrivateKey(CertModuleItf& module, const String& password);
    Error                             CheckCertificateChain(const Array<crypto::x509::Certificate>& chain);
    Error                             SyncValidCerts(CertModuleItf& module);
    Error                             TrimCerts(CertModuleItf& module, const String& password);

    StorageItf&                                          mStorage;
    crypto::x509::CertificateProviderItf&                mCertProvider;
    Mutex                                                mMutex;
    StaticArray<CertModuleItf*, cIAMCertModulesMaxCount> mModules;
};

/** @}*/

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
