/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_MOCK_X509PROVIDER_HPP_
#define AOS_MOCK_X509PROVIDER_HPP_

#include "aos/common/crypto.hpp"
#include <gmock/gmock.h>

namespace aos {
namespace crypto {
namespace x509 {

class MockProvider : public ProviderItf {
public:
    MOCK_METHOD(Error, CreateCertificate,
        (const Certificate& templ, const Certificate& parent, const PrivateKeyItf& privKey, Array<uint8_t>& pemCert),
        (override));
    MOCK_METHOD(Error, PEMToX509Certs, (const Array<uint8_t>& pemBlob, Array<Certificate>& resultCerts), (override));
    MOCK_METHOD(RetWithError<SharedPtr<PrivateKeyItf>>, PEMToX509PrivKey, (const Array<uint8_t>& pemBlob), (override));
    MOCK_METHOD(Error, DERToX509Cert, (const Array<uint8_t>& derBlob, Certificate& resultCerts), (override));
    MOCK_METHOD(Error, CreateCSR, (const CSR& templ, const PrivateKeyItf& privKey, Array<uint8_t>& pemCSR), (override));
    MOCK_METHOD(Error, CreateDN, (const String& commonName, Array<uint8_t>& result), (override));
    MOCK_METHOD(Error, DNToString, (const Array<uint8_t>& dn, String& result), (override));
};

} // namespace x509
} // namespace crypto
} // namespace aos

#endif
