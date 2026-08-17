/*
 * Copyright (c) 2025 Renesas Electronics Corporation and/or its affiliates
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is a derived work from Renesas r_rsip_cm_rx (rx-driver-package).
 * Original copyright is retained under the BSD-3-Clause license terms.
 *
 * rsip_ecdsa_p256_sha256.h
 * RSIP-E11A (RX261) SHA-256 and ECDSA P-256 verify for a bootloader.
 * Compatibility Mode only. No interrupt service.
 */

#ifndef RSIP_ECDSA_P256_SHA256_H
#define RSIP_ECDSA_P256_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RSIP_SHA256_DIGEST_SIZE          32u
#define RSIP_SHA256_BLOCK_SIZE           64u
#define RSIP_ECDSA_P256_HASH_SIZE        32u
#define RSIP_ECDSA_P256_PUBKEY_SIZE      65u  /* SEC1: 0x04 || X || Y */
#define RSIP_ECDSA_P256_SIG_SIZE         64u  /* raw r || s */

struct rsip_sha256_ctx {
    uint32_t state[8];
    uint32_t total_lo;
    uint32_t total_hi;
    uint8_t  buffer[RSIP_SHA256_BLOCK_SIZE];
    uint32_t buffer_len;
};

/* Call once before SHA or ECDSA. Loads HUK. Without HUK, later primitives can hang. */
int rsip_hw_init(void);

/* Multipart SHA-256 so the caller can feed salt then message as separate updates. */
int rsip_sha256_init(struct rsip_sha256_ctx *ctx);
int rsip_sha256_update(struct rsip_sha256_ctx *ctx, const uint8_t *data, size_t len);
int rsip_sha256_finish(struct rsip_sha256_ctx *ctx, uint8_t digest[RSIP_SHA256_DIGEST_SIZE]);

/* One-shot SHA-256. Own path with state[8] only; shares compress/pad helpers
 * with multipart. Prefer this when the message is contiguous. */
int rsip_sha256_compute(const uint8_t *msg, size_t len,
                        uint8_t digest[RSIP_SHA256_DIGEST_SIZE]);

/* Empty-message vector. Faster than ECDSA self-test for a basic RSIP health check. */
int rsip_sha256_selftest(void);

/*
 * hash and sig: FIPS/big-endian byte images, same layout as mbedtls_mpi_write_binary
 * for this CM path. pubkey is SEC1 65-byte form only (no length argument).
 * Does not hash the message; the caller supplies the digest (for example after salt||msg).
 */
int rsip_ecdsa_p256_verify_hash(
    const uint8_t hash[RSIP_ECDSA_P256_HASH_SIZE],
    const uint8_t sig[RSIP_ECDSA_P256_SIG_SIZE],
    const uint8_t pubkey[RSIP_ECDSA_P256_PUBKEY_SIZE]);

/* RFC 6979 A.2.5 ("sample"). Also checks that a flipped signature bit fails. */
int rsip_ecdsa_p256_selftest(void);

#ifdef __cplusplus
}
#endif
#endif /* RSIP_ECDSA_P256_SHA256_H */
