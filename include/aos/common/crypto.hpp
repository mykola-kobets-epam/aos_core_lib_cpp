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
constexpr auto cCertPubKeySize = AOS_CONFIG_CRYPTO_CERT_PUB_KEY_SIZE;

/**
 * Certificate serial number max length.
 */
constexpr auto cCertSerialNumberSize = AOS_CONFIG_CRYPTO_CERT_SERIAL_SIZE;

/**
 * Certificate issuer name max length.
 */
constexpr auto cCertIssuerSize = AOS_CONFIG_CRYPTO_CERT_ISSUER_SIZE;

/**
 * Max length of a DNS name.
 */
constexpr auto cDNSNameLen = AOS_CONFIG_CRYPTO_DNS_NAME_LEN;

/**
 * Max number of alternative names for a module.
 */
constexpr auto cAltDNSNamesCount = AOS_CONFIG_CRYPTO_ALT_DNS_NAMES_MAX_COUNT;

/**
 * Certificate subject size.
 */
constexpr auto cCertSubjSize = AOS_CONFIG_CRYPTO_CERT_ISSUER_SIZE;

/**
 * Certificate extra extensions max number.
 */
constexpr auto cCertExtraExtCount = AOS_CONFIG_CRYPTO_EXTRA_EXTENSIONS_COUNT;

/**
 * Maximum length of numeric string representing ASN.1 Object Identifier.
 */
constexpr auto cASN1ObjIdLen = AOS_CONFIG_CRYPTO_ASN1_OBJECT_ID_LEN;

/**
 * Maximum size of a certificate ASN.1 Extension Value.
 */
constexpr auto cASN1ExtValueSize = AOS_CONFIG_CRYPTO_ASN1_EXTENSION_VALUE_SIZE;

/**
 * Maximum certificate key id size(in bytes).
 */
constexpr auto cCertKeyIdSize = AOS_CONFIG_CRYPTO_CERT_KEY_ID_SIZE;

/**
 * Maximum size of a PEM certificate.
 */
constexpr auto cPEMCertSize = AOS_CONFIG_CRYPTO_PEM_CERT_SIZE;

/**
 * General certificate private key type.
 */
class PrivateKey {
public:
    /**
     * Returns public part of a private key.
     */
    const Array<uint8_t>& GetPublic() const { return mPublicKey; }

private:
    StaticArray<uint8_t, cCertPubKeySize> mPublicKey;
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
    StaticArray<uint8_t, cASN1ExtValueSize> mValue;

    /**
     * Checks whether current object is equal the the given one.
     *
     * @param extension object to compare with.
     * @return bool.
     */
    bool operator==(const Extension& extension) const { return extension.mId == mId && extension.mValue == mValue; }
    /**
     * Checks whether current object is not equal the the given one.
     *
     * @param extension object to compare with.
     * @return bool.
     */
    bool operator!=(const Extension& extension) const { return !operator==(extension); }
};

/**
 * Encodes array of object identifiers into ASN1 value.
 *
 * @param src array of object identifiers.
 * @param asn1Value result ASN1 value.
 */

inline void Encode(const Array<ObjectIdentifier>& src, Array<uint8_t>& asn1Value)
{
    (void)src;
    (void)asn1Value;
}

} // namespace asn1

namespace x509 {

/**
 * x509 Certificate.
 */
struct Certificate {
    /**
     * Certificate subject.
     */
    StaticArray<uint8_t, cCertSubjSize> mSubject;
    /**
     * Certificate subject key id.
     */
    StaticArray<uint8_t, cCertKeyIdSize> mSubjectKeyId;
    /**
     * Certificate authority key id.
     */
    StaticArray<uint8_t, cCertKeyIdSize> mAuthorityKeyId;
    /**
     * Certificate issuer.
     */
    StaticArray<uint8_t, cCertIssuerSize> mIssuer;
    /**
     * Certificate serial number.
     */
    StaticArray<uint8_t, cCertSerialNumberSize> mSerial;
    /**
     * Certificate validity period.
     */
    time::Time mNotBefore, mNotAfter;
};

/**
 * x509 Certificate request.
 */
struct CSR {
    /**
     * Certificate subject size.
     */
    StaticArray<uint8_t, cCertSubjSize> mSubject;
    /**
     * Alternative DNS names.
     */
    StaticArray<StaticString<cDNSNameLen>, cAltDNSNamesCount> mDNSNames;
    /**
     * Contains extra extensions applied to CSR.
     */
    StaticArray<asn1::Extension, cCertExtraExtCount> mExtraExtensions;
};

/**
 * Provides interface to manage certificate requests.
 */
class ProviderItf {
public:
    /**
     * Creates a new certificate based on a template.
     *
     * @param templ a pattern for a new certificate.
     * @param parent a parent certificate in a certificate chain.
     * @param pubKey public key.
     * @param privKey private key.
     * @param[out] resultCert result certificate in PEM format.
     * @result Error.
     */
    virtual Error CreateCertificate(
        const Certificate& templ, const Certificate& parent, const PrivateKey& privKey, Array<uint8_t>& pemCert)
        = 0;

    /**
     * Reads certificates from a PEM blob.
     *
     * @param pemBlob raw certificates in a PEM format.
     * @param[out] resultCerts result certificate chain.
     * @result Error.
     */
    virtual Error PEMToX509Certs(const Array<uint8_t>& pemBlob, Array<Certificate>& resultCerts) = 0;

    /**
     * Creates a new certificate request, based on a template.
     *
     * @param templ template for a new certificate request.
     * @param privKey private key.
     * @param[out] pemCSR result CSR in PEM format.
     * @result Error.
     */
    virtual Error CreateCSR(const CSR& templ, const PrivateKey& privKey, Array<uint8_t>& pemCSR) = 0;

    /**
     * Constructs x509 distinguished name(DN) from the argument list.
     *
     * @param comName common name.
     * @param[out] result result DN.
     * @result Error.
     */
    virtual Error CreateDN(const String& commonName, Array<uint8_t>& result) = 0;

    /**
     * Returns text representation of x509 distinguished name(DN).
     *
     * @param dn source binary representation of DN.
     * @param[out] result DN text representation.
     * @result Error.
     */
    virtual Error DNToString(const Array<uint8_t>& dn, String& result) = 0;

    /**
     * Destroys object instance.
     */
    virtual ~ProviderItf() = default;
};

} // namespace x509
} // namespace crypto
} // namespace aos

#endif
