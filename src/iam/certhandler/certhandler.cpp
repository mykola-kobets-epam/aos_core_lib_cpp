/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/iam/certhandler.hpp"
#include "log.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

CertHandler::CertHandler(StorageItf& storage, crypto::x509::CertificateProviderItf& certProvider)
    : mStorage(storage)
    , mCertProvider(certProvider)
{
}

Error CertHandler::RegisterModule(CertModuleItf& module)
{
    LockGuard lock(mMutex);
    LOG_INF() << "Register module with cert type: " << module.GetCertType();

    mModules.PushBack(&module);
    return SyncValidCerts(module);
}

void CertHandler::GetCertTypes(Array<StaticString<cCertificateTypeLen>>& certTypes)
{
    LockGuard lock(mMutex);

    for (const auto module : mModules) {
        certTypes.PushBack(module->GetCertType());
    }
}

Error CertHandler::SetOwner(const String& certType, const String& password)
{
    LockGuard lock(mMutex);

    auto* module = FindModule(certType);
    if (module == nullptr) {
        return Error::Enum::eNotFound;
    }

    return module->SetOwner(password);
}

Error CertHandler::Clear(const String& certType)
{
    LockGuard lock(mMutex);

    auto* module = FindModule(certType);
    if (module == nullptr) {
        return Error::Enum::eNotFound;
    }

    Error error = module->Clear();
    if (error != Error::Enum::eNone) {
        return error;
    }

    return mStorage.RemoveAllCertsInfo(certType);
}

Error CertHandler::CreateKey(
    const String& certType, const String& subject, const String& password, crypto::x509::CSR& csr)
{
    LockGuard lock(mMutex);

    auto* module = FindModule(certType);
    if (module == nullptr) {
        return Error::Enum::eNotFound;
    }

    auto key = CreatePrivateKey(*module, password);
    if (key.mError != Error::Enum::eNone) {
        return key.mError;
    }

    return module->CreateCSR(subject, *key.mValue, csr);
}

Error CertHandler::ApplyCertificate(const String& certType, const Array<uint8_t>& cert, CertInfo& info)
{
    LockGuard lock(mMutex);

    auto* module = FindModule(certType);
    if (module == nullptr) {
        return Error::Enum::eNotFound;
    }

    StaticArray<crypto::x509::Certificate, cCertChainSize> certificates;
    Error error = mCertProvider.CreateCertificatesFromPEM(cert, certificates);
    if (error != Error::Enum::eNone) {
        return error;
    }

    error = CheckCertificateChain(certificates);
    if (error != Error::Enum::eNone) {
        return error;
    }

    StaticString<cPasswordLen> password;
    error = module->ApplyCertificateChain(certificates, info, password);
    if (error != Error::Enum::eNone) {
        return error;
    }

    error = mStorage.AddCertInfo(certType, info);
    if (error != Error::Enum::eNone) {
        return error;
    }

    return TrimCerts(*module, password);
}

RetWithError<CertInfo> CertHandler::GetCertificate(
    const String& certType, const Array<uint8_t>& issuer, const String& serial)
{
    LockGuard lock(mMutex);

    if (serial == "") {
        StaticArray<CertInfo, cCertsPerModule> certsInfo;
        const Error                            certsInfoErr = mStorage.GetCertsInfo(certType, certsInfo);
        if (certsInfoErr != Error::Enum::eNone) {
            return {CertInfo {}, certsInfoErr};
        }

        if (certsInfo.Size() == 0) {
            return {CertInfo {}, Error::Enum::eNotFound};
        }

        CertInfo result = {};
        for (const auto& item : certsInfo) {
            if (result.mNotAfter.IsZero() || item.mNotAfter < result.mNotAfter) {
                result = item;
            }
        }
        return {result, Error::Enum::eNone};
    }

    StaticString<crypto::cCertificateIssuerLen> issuerStr;
    crypto::Base64Encoder::Encode(issuer, issuerStr);
    return mStorage.GetCertInfo(issuerStr, serial);
}

Error CertHandler::CreateSelfSignedCert(const String& certType, const String& password)
{
    LockGuard lock(mMutex);

    auto* module = FindModule(certType);
    if (module == nullptr) {
        return Error::Enum::eNotFound;
    }

    auto key = CreatePrivateKey(*module, password);
    if (key.mError != Error::Enum::eNone) {
        return key.mError;
    }

    static constexpr auto cValidSelfSignedCertPeriod = 100; // in years
    // TODO: probably we need to provide BigInt type for this case. clarify!
    const uint64_t serial = time::Time::Now().UnixNano();

    crypto::x509::Certificate templ;
    templ.mSerial = Array<uint8_t>(reinterpret_cast<const uint8_t*>(serial), sizeof(serial));
    templ.mNotBefore = time::Time::Now();
    templ.mNotAfter = time::Time::Now().AddYears(cValidSelfSignedCertPeriod);
    templ.mSubject = "Aos Core";

    DynamicArray<uint8_t, cMaxSelfSignedCertSize> pemCert;
    const Error error = mCertProvider.CreateCertificate(templ, templ, *key.mValue, pemCert);
    if (error != Error::Enum::eNone) {
        return error;
    }

    CertInfo certInfo;
    return ApplyCertificate(certType, pemCert, certInfo);
}

CertHandler::~CertHandler()
{
    LOG_DBG() << "Close certificate handler";
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

Error CertHandler::CheckCertificateChain(const Array<crypto::x509::Certificate>& chain)
{
    if (chain.IsEmpty()) {
        return Error::Enum::eNotFound;
    }

    for (const auto& cert : chain) {
        LOG_DBG() << "Check certificate chain: "
                  << "[ issuer: " << cert.mIssuer << ", subject: " << cert.mSubject << " ]";
    }

    // TODO: clairfy whther Issuer/Subject test is ok (source impl. tested RawIssuer/RawSubject instead).
    unsigned currentCert = 0;
    while (!(chain[currentCert].mIssuer.IsEmpty() || chain[currentCert].mIssuer == chain[currentCert].mSubject)) {
        unsigned parentCert = 0;
        bool     parentFound = false;
        for (unsigned i = 0; i < chain.Size(); i++) {
            if (i == currentCert) {
                continue;
            }

            if (chain[currentCert].mIssuer == chain[i].mSubject
                || chain[currentCert].mAuthorityKeyId == chain[i].mSubjectKeyId) {
                parentCert = i;
                parentFound = true;
                break;
            }
        }

        if (!parentFound) {
            return Error::Enum::eNotFound;
        }

        currentCert = parentCert;
    }
    return Error::Enum::eNone;
}

CertModuleItf* CertHandler::FindModule(const String& certType)
{
    for (const auto module : mModules) {
        if (module->GetCertType() == certType) {
            return module;
        }
    }
    return nullptr;
}

RetWithError<crypto::PrivateKey*> CreatePrivateKey(CertModuleItf& module, const String& password)
{
    // TODO: RemoveInvalidCerts/RemoveInvalidKeys dont remove certs from storage. clarify!
    Error error = module.RemoveInvalidCerts(password);
    if (error != Error::Enum::eNone) {
        return {nullptr, error};
    }
    error = module.RemoveInvalidKeys(password);
    if (error != Error::Enum::eNone) {
        return {nullptr, error};
    }

    auto key = module.CreateKey(password);
    if (key.mError != Error::Enum::eNone) {
        return key;
    }
    return key;
}

Error CertHandler::SyncValidCerts(CertModuleItf& module)
{
    if (module.GetModuleConfig().mSkipValidation) {
        LOG_WRN() << "Skip validation: "
                  << "[ certType: " << module.GetCertType() << " ]";
    }

    const Array<CertInfo>& validCerts = module.GetValidCerts();

    StaticArray<CertInfo, cCertsPerModule> certsInStorage;
    Error                                  error = mStorage.GetCertsInfo(module.GetCertType(), certsInStorage);
    if (error != Error::Enum::eNone || error != Error::Enum::eNotFound) {
        return error;
    }

    // Add module certificates to storage.
    for (const auto& moduleCert : validCerts) {
        CertInfo* storedCert = nullptr;
        for (auto& cert : certsInStorage) {
            if (cert == moduleCert) {
                storedCert = &cert;
            }
        }

        if (storedCert != nullptr) {
            certsInStorage.Remove(storedCert);
        } else {
            LOG_WRN() << "Add missing cert to DB ["
                      << "certType: " << module.GetCertType() << ", certURL: " << moduleCert.mCertURL
                      << ", keyURL: " << moduleCert.mKeyURL << ", notAfter: " << moduleCert.mNotAfter << "]";

            error = mStorage.AddCertInfo(module.GetCertType(), moduleCert);
            if (error != Error::Enum::eNone) {
                return error;
            }
        }
    }

    // Remove outdated certificates from storage.
    for (const auto& moduleCert : certsInStorage) {
        LOG_WRN() << "Remove invalid cert from DB ["
                  << "certType: " << module.GetCertType() << ", certURL: " << moduleCert.mCertURL
                  << ", keyURL: " << moduleCert.mKeyURL << ", notAfter: " << moduleCert.mNotAfter << "]";
        error = mStorage.RemoveCertInfo(module.GetCertType(), moduleCert.mCertURL);
        if (error != Error::Enum::eNone) {
            return error;
        }
    }
    return Error::Enum::eNone;
}

Error CertHandler::TrimCerts(CertModuleItf& module, const String& password)
{
    StaticArray<CertInfo, cCertsPerModule> certsInfo;
    Error                                  error = mStorage.GetCertsInfo(module.GetCertType(), certsInfo);
    if (error != Error::Enum::eNone && error != Error::Enum::eNotFound) {
        LOG_ERR() << "Can' get certificates: [certType: " << module.GetCertType() << "]";
        return error;
    }

    if (certsInfo.Size() > module.GetModuleConfig().mMaxCertificates) {
        LOG_WRN() << "Current cert count exceeds max count: " << certsInfo.Size() << ">"
                  << module.GetModuleConfig().mMaxCertificates << ". Remove old certificates";
    }

    while (certsInfo.Size() > module.GetModuleConfig().mMaxCertificates) {
        time::Time minTime;
        CertInfo*  info = nullptr;
        for (auto& cert : certsInfo) {
            if (minTime.IsZero() || cert.mNotAfter < minTime) {
                minTime = cert.mNotAfter;
                info = &cert;
            }
        }

        error = module.RemoveCertificateChain(info->mCertURL, password);
        if (error != Error::Enum::eNone) {
            return error;
        }

        error = module.RemoveKey(info->mKeyURL, password);
        if (error != Error::Enum::eNone) {
            return error;
        }

        error = mStorage.RemoveCertInfo(module.GetCertType(), info->mCertURL);
        if (error != Error::Enum::eNone) {
            return error;
        }

        certsInfo.Remove(info);
    }
    return Error::Enum::eNone;
}

} // namespace certhandler
} // namespace iam
} // namespace aos
