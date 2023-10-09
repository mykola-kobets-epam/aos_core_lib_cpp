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

namespace aos {
namespace crypto {

/**
 * General certificate private key type.
 */
using PrivateKey = String;

namespace x509 {

/**
 * x509 certificate type.
 */
using Certificate = Array<uint8_t>;
} // namespace x509
} // namespace crypto
} // namespace aos

#endif
