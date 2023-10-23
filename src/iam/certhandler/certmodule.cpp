/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/iam/certmodule.hpp"
#include "log.hpp"

namespace aos {
namespace iam {
namespace certhandler {

/***********************************************************************************************************************
 *  CertInfo method.
 *  TODO: clarify whether it is required to check all the fields.
 **********************************************************************************************************************/
bool CertInfo::operator==(const CertInfo& certInfo) const
{
    return certInfo.mCertURL == mCertURL && certInfo.mIssuer == mIssuer && certInfo.mKeyURL == mKeyURL
        && certInfo.mNotAfter == mNotAfter && certInfo.mSerial == mSerial;
}

/***********************************************************************************************************************
 * CertModuleItf implementation
 **********************************************************************************************************************/

CertModuleItf::CertModuleItf(crypto::x509::CSRProviderItf& csrProvider)
    : mCsrProvider(csrProvider)
{
}

Error CertModuleItf::CreateCSR(const String& subject, const crypto::PrivateKey& privKey, crypto::x509::CSR& csr)
{
    crypto::x509::CSR templ;
    templ.mSubject = subject;
    templ.mDnsNames = GetModuleConfig().mAlternativeNames;
    // templ.
    static constexpr auto oidExtensionExtendedKeyUsage = "2.5.29.37";
    static constexpr auto oidExtKeyUsageClientAuth = "1.3.6.1.5.5.7.3.1";
    static constexpr auto oidExtKeyUsageServerAuth = "1.3.6.1.5.5.7.3.2";

    crypto::asn1::ObjectIdentifier oid;
    for (const auto& extKeyUsage : GetModuleConfig().mExtendedKeyUsage) {
        switch (extKeyUsage.GetValue()) {
        case ExtendedKeyUsageEnum::eClientAuth:
            oid = oidExtKeyUsageClientAuth;
            break;
        case ExtendedKeyUsageEnum::eServerAuth:
            oid = oidExtKeyUsageServerAuth;
            break;
        default:
            LOG_WRN() << "Unexpected extended key usage value: " << extKeyUsage.ToString();
            break;
        }
    }

    if (!oid.IsEmpty()) {
        StaticArray<uint8_t, crypto::cCertExtValueSize> extValue;
        crypto::asn1::Encode(oid, extValue);

        crypto::asn1::Extension ext;
        ext.mId = oidExtensionExtendedKeyUsage;
        ext.mValue.PushBack(extValue);

        templ.mExtraExtensions.PushBack(ext);
    }

    return mCsrProvider.CreateCSR(templ, privKey, csr);
}

const String& CertModuleItf::GetCertType() const
{
    return mCertType;
}

const Array<CertInfo>& CertModuleItf::GetValidCerts() const
{
    return mValidCerts;
}

Error CertModuleItf::RemoveInvalidCerts(const String& password)
{
    for (const auto& url : mInvalidCerts) {
        LOG_WRN() << "Remove invalid cert ["
                  << "certType: " << GetCertType() << ", URL: " << url << "]";
        const Error error = RemoveCertificateChain(url, password);
        if (error != Error::Enum::eNone) {
            return error;
        }
    }

    mInvalidCerts.Clear();
    return Error::Enum::eNone;
}

Error CertModuleItf::RemoveInvalidKeys(const String& password)
{
    for (const auto& url : mInvalidKeys) {
        LOG_WRN() << "Remove invalid key ["
                  << "certType: " << GetCertType() << ", URL: " << url << "]";
        const Error error = RemoveKey(url, password);
        if (error != Error::Enum::eNone) {
            return error;
        }
    }

    mInvalidKeys.Clear();
    return Error::Enum::eNone;
}

} // namespace certhandler
} // namespace iam
} // namespace aos
