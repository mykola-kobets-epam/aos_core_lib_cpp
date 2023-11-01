/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_MOCK_STORAGE_HPP_
#define AOS_MOCK_STORAGE_HPP_

#include "aos/iam/certhandler.hpp"
#include <gmock/gmock.h>

namespace aos {
namespace iam {
namespace certhandler {

/**
 * StorageItf provides API to store/retrieve certificates info.
 */
class MockStorage : public StorageItf {
public:
    MOCK_METHOD(Error, AddCertInfo, (const String& certType, const CertInfo& certInfo), (override));
    MOCK_METHOD(Error, GetCertInfo, (const Array<uint8_t>& issuer, const Array<uint8_t>& serial, CertInfo& resCert),
        (override));
    MOCK_METHOD(Error, GetCertsInfo, (const String& certType, Array<CertInfo>& certsInfo), (override));
    MOCK_METHOD(Error, RemoveCertInfo, (const String& certType, const String& certURL), (override));
    MOCK_METHOD(Error, RemoveAllCertsInfo, (const String& certType), (override));
};

} // namespace certhandler
} // namespace iam
} // namespace aos

#endif
