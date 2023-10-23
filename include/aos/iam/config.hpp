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
#ifndef AOS_CONFIG_CERTMODULE_CERT_TYPE_NAME_LEN
#define AOS_CONFIG_CERTMODULE_CERT_TYPE_NAME_LEN 16
#endif

/**
 * Max number of key usages for a module.
 */
#ifndef AOS_CONFIG_CERTMODULE_KEY_USAGE_MAX_COUNT
#define AOS_CONFIG_CERTMODULE_KEY_USAGE_MAX_COUNT 10
#endif

/**
 * Max length of key usage name.
 */
#ifndef AOS_CONFIG_CERTMODULE_KEY_USAGE_LEN
#define AOS_CONFIG_CERTMODULE_KEY_USAGE_LEN 20
#endif

/**
 * Max number of certificate modules.
 */
#ifndef AOS_CONFIG_CERTHANDLER_MODULES_MAX_COUNT
#define AOS_CONFIG_CERTHANDLER_MODULES_MAX_COUNT 10
#endif

/**
 * Max expected number of certificates in a chain stored in PEM file.
 */
#ifndef AOS_CONFIG_CERTHANDLER_CERTS_CHAIN_SIZE
#define AOS_CONFIG_CERTHANDLER_CERTS_CHAIN_SIZE 5
#endif

/**
 * Max expected number of certificates per IAM certificate module.
 */
#ifndef AOS_CONFIG_CERTHANDLER_MAX_CERTS_PER_MODULE
#define AOS_CONFIG_CERTHANDLER_MAX_CERTS_PER_MODULE 5
#endif

/**
 * Max size of self signed certificate in PEM format (in bytes).
 */
#ifndef AOS_CONFIG_CERTHANDLER_PEM_SELFSIGNED_CERT_SIZE
#define AOS_CONFIG_CERTHANDLER_PEM_SELFSIGNED_CERT_SIZE 2048 + 1024
#endif

/**
 * Max number of invalid certificates per module.
 */
#ifndef AOS_CONFIG_CERTHANDLER_INVALID_CERT_PER_MODULE
#define AOS_CONFIG_CERTHANDLER_INVALID_CERT_PER_MODULE 10
#endif

/**
 * Max number of invalid keys per module.
 */
#ifndef AOS_CONFIG_CERTHANDLER_INVALID_KEYS_PER_MODULE
#define AOS_CONFIG_CERTHANDLER_INVALID_KEYS_PER_MODULE 10
#endif

/**
 * Password length.
 */
#ifndef AOS_CONFIG_CERTHANDLER_PASSWORD_LEN
#define AOS_CONFIG_CERTHANDLER_PASSWORD_LEN 40
#endif

#endif
