/**
 * @file rsip_ecdsa_p256_sha256.h
 * @brief Minimal RSIP-E11A SHA-256 + ECDSA P-256 verify for RX261 bootloader
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Derived from Renesas r_rsip_cm_rx (rx-driver-package)
 */
#ifndef RSIP_ECDSA_P256_SHA256_H
#define RSIP_ECDSA_P256_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RSIP_SHA256_DIGEST_SIZE          32u
#define RSIP_ECDSA_P256_HASH_SIZE        32u
/** SEC1 uncompressed public key: 0x04 || X || Y */
#define RSIP_ECDSA_P256_PUBKEY_SIZE      65u
/** Raw signature r || s */
#define RSIP_ECDSA_P256_SIG_SIZE         64u

/**
 * Release module-stop, SoftwareReset, SelfCheck1/2, LE mode, HUK load.
 * Call once before any crypto API.
 * @return 0 on success, negative on failure
 */
int rsip_hw_init(void);

/** One-shot SHA-256. digest is FIPS big-endian byte order (32 bytes). */
int rsip_sha256_compute(const uint8_t *msg, size_t len,
                        uint8_t digest[RSIP_SHA256_DIGEST_SIZE]);

/** SHA-256 self-test (empty message). 0 = pass. */
int rsip_sha256_selftest(void);

/**
 * ECDSA-P256 verify over a SHA-256 digest.
 * @param hash   32-byte digest (FIPS BE)
 * @param sig    64-byte r||s
 * @param pubkey 65-byte 0x04||X||Y
 * @return 0 = valid; -1 = bad pubkey prefix; other = HW error
 *
 * hash/sig/(pubkey+1) are passed as (const uint32_t *) when 4-byte aligned.
 */
int rsip_ecdsa_p256_verify_hash(
    const uint8_t hash[RSIP_ECDSA_P256_HASH_SIZE],
    const uint8_t sig[RSIP_ECDSA_P256_SIG_SIZE],
    const uint8_t pubkey[RSIP_ECDSA_P256_PUBKEY_SIZE]);

/** ECDSA self-test (RFC 6979 A.2.5 "sample"). 0 = pass. */
int rsip_ecdsa_p256_selftest(void);

#ifdef __cplusplus
}
#endif
#endif /* RSIP_ECDSA_P256_SHA256_H */
