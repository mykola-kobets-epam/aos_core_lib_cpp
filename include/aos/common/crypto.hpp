/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CRYPTO_HPP_
#define AOS_CRYPTO_HPP_

#include "aos/common/tools/array.hpp"
#include "aos/common/tools/string.hpp"

#include "aos/common/time.hpp"
#include "aos/common/types.hpp"

namespace aos {
namespace crypto {

/**
 * Certificate public key len.
 */
constexpr auto cCertificatePubKeyLen = AOS_CONFIG_CRYPTO_CERT_PUB_KEY_LEN;

/**
 * Certificate private key len.
 */
constexpr auto cCertificatePrivKeyLen = AOS_CONFIG_CRYPTO_CERT_PRIV_KEY_LEN;

/**
 * Certificate type max length.
 */
constexpr auto cCertificateTypeLen = AOS_CONFIG_CRYPTO_CERTIFICATE_TYPE_LEN;

/**
 * Certificate serial number max length.
 */
constexpr auto cCertificateSerialNumberLen = AOS_CONFIG_CRYPTO_CERT_SERIAL_LEN;

/**
 * Certificate issuer name max length.
 */
constexpr auto cCertificateIssuerLen = AOS_CONFIG_CRYPTO_CERT_ISSUER_ID_LEN;

/**
 * Password max length.
 */
constexpr auto cPasswordLen = AOS_CONFIG_CRYPTO_PASSWORD_LEN;

/**
 * Max length of alternative module name.
 */
constexpr auto cDnsNameLen = AOS_CONFIG_CRYPTO_DNS_NAME_LEN;

/**
 * Max number of alternative names for a module.
 */
constexpr auto cAltDnsNamesCount = AOS_CONFIG_CRYPTO_ALT_DNS_NAMES_MAX_COUNT;

/**
 * Certificate subject size.
 */
constexpr auto cCertificateSubjSize = AOS_CONFIG_CRYPTO_CERT_SUBJECT_SIZE;

/**
 * Raw CSR max size.
 */
constexpr auto cRawCSRSize = AOS_CONFIG_CRYPTO_RAW_CSR_SIZE;

/**
 * Certificate extra extrnsions max number.
 */
constexpr auto cCertificateExtraExtCount = AOS_CONFIG_CRYPTO_EXTRA_EXTENSIONS_COUNT;

/**
 * Maximum length of numeric string representing ASN.1 Object Identifier.
 */
constexpr auto cASN1ObjIdLen = AOS_CONFIG_CRYPTO_OBJECT_ID_LEN;

/**
 * Maximum size of a certificate extension value.
 */
constexpr auto cCertExtValueSize = AOS_CONFIG_CRYPTO_CERT_EXTENSION_VALUE_SIZE;

/**
 * General certificate private key type.
 */
class PrivateKey {
public:
    /**
     * Returns public part of a private key.
     */
    const Array<uint8_t>& GetPublic() const { return mPublicKey; }

    /**
     * Returns private part of a private key.
     */
    const Array<uint8_t>& GetPrivate() const { return mPublicKey; }

private:
    StaticArray<uint8_t, cCertificatePubKeyLen>  mPublicKey;
    StaticArray<uint8_t, cCertificatePrivKeyLen> mPrivateKey;
};

namespace asn1 {
/**
 * ASN.1 OBJECT IDENTIFIER
 */
using ObjectIdentifier = StaticString<cASN1ObjIdLen>;

/**
 * ASN.1 structure extension. RFC 580, section 4.2
 */
struct Extension {
    ObjectIdentifier                        mId;
    StaticArray<uint8_t, cCertExtValueSize> mValue;
};
} // namespace asn1

namespace x509 {

/**
 * x509 Certificate.
 */
struct Certificate {
    /**
     * Certificate subject size.
     */
    StaticString<cCertificateSubjSize> mSubject;
    /**
     * Certificate issuer name.
     */
    StaticString<cCertificateIssuerLen> mIssuer;
    /**
     * Certificate serial number.
     */
    StaticString<cCertificateSerialNumberLen> mSerial;
    /**
     * Certificate validity period.
     */
    time::Time mNotBefore, mNotAfter;
};

/**
 * Provides interface to manage certificates.
 */
class CertificateProviderItf {
public:
    /**
     * Creates a new certificate based on a template.
     *
     * @param templ a pattern for a new certificate.
     * @param parent a parent certificate in a certificate chain.
     * @param pubKey public key.
     * @param privKey private key.
     * @param[out] resultCert a new generated certificate.
     * @result Error.
     */
    virtual Error CreateCertificate(
        const Certificate& templ, const Certificate& parent, const PrivateKey& privKey, Certificate& resultCert)
        = 0;

    /**
     * Creates certificate from a PEM blob.
     *
     * @param pemBlob raw certificate in a PEM format.
     * @param[out] resultCert result certificate.
     * @result Error.
     */
    virtual Error CreateCertificateFromPEM(const Array<uint8_t>& pemBlob, Certificate& resultCert) = 0;

    /**
     * Destroys object instace.
     */
    virtual ~CertificateProviderItf() = default;
};

/**
 * x509 Certificate request.
 */
struct CSR {
    /**
     * Raw CSR content.
     */
    StaticArray<uint8_t, cRawCSRSize> mRaw;
    /**
     * Certificate subject size.
     */
    StaticString<cCertificateSubjSize> mSubject;
    /**
     * Alternative DNS names.
     */
    StaticArray<StaticString<cDnsNameLen>, cAltDnsNamesCount> mDnsNames;
    /**
     * Contains extra extensions applied to CSR.
     */
    StaticArray<asn1::Extension, cCertificateExtraExtCount> mExtraExtensions;
};

/**
 * Provides interface to manage certificate requests.
 */
class CSRProviderItf {
public:
    /**
     * Creates a new certificate request, based on a template.
     *
     * @param template a pattern for a new certificate.
     * @param privKey private key.
     * @param[out] resultCSR generated CSR.
     * @result Error.
     */
    virtual Error CreateCSR(const Certificate& templ, const PrivateKey& privKey, CSR& resultCSR) = 0;

    /**
     * Destroys object instace.
     */
    virtual ~CSRProviderItf() = default;
};

} // namespace x509
} // namespace crypto
} // namespace aos

#endif
