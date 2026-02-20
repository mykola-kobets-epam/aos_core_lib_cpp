/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_COMMON_CRYPTO_ITF_PKCS11URL_HPP_
#define AOS_CORE_COMMON_CRYPTO_ITF_PKCS11URL_HPP_

#include <core/common/consts.hpp>
#include <core/common/tools/array.hpp>
#include <core/common/tools/string.hpp>

#include "x509.hpp"

namespace aos::pkcs11 {

/**
 * Maximum size of PKCS11 ID.
 */
constexpr auto cIDSize = AOS_CONFIG_PKCS11_ID_SIZE;

/**
 * Maximum length of PKCS11 token label.
 */
constexpr auto cLabelLen = AOS_CONFIG_PKCS11_LABEL_LEN;

/**
 * Certificate URL.
 */
struct PKCS11URL {
    StaticArray<uint8_t, cIDSize> mID;
    StaticString<cLabelLen>       mLabel;
};

/**
 * A chain of certificate URLs.
 */
using CertificateURLChain = StaticArray<PKCS11URL, crypto::cCertChainSize>;

} // namespace aos::pkcs11

#endif
