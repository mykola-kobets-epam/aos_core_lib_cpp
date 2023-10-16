/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_IAM_CONFIG_HPP_
#define AOS_IAM_CONFIG_HPP_

/**
 * Max length of certificate type.
 */
#ifndef AOS_IAM_CERTIFICATE_TYPE_NAME_LEN
#define AOS_IAM_CERTIFICATE_TYPE_NAME_LEN 16
#endif

/**
 * Max number of key usages for a module.
 */
#ifndef AOS_IAM_TYPES_MODULE_KEY_USAGE_MAX_COUNT
#define AOS_IAM_TYPES_MODULE_KEY_USAGE_MAX_COUNT 10
#endif

/**
 * Max length of key usage name.
 */
#ifndef AOS_IAM_TYPES_MODULE_KEY_USAGE_LEN
#define AOS_IAM_TYPES_MODULE_KEY_USAGE_LEN 20
#endif

#endif
