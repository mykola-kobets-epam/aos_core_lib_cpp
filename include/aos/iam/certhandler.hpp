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
     * @param password owner password.
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
