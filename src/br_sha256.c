#include <stddef.h>
#include <stdint.h>
#include <bearssl_hash.h>
#include <bearssl_ec.h>

int compute_sha256_by_bearssl(const void* data, size_t data_len, uint8_t digest_out[32])
{
    br_sha256_context sha_ctx;

    const uint8_t* data_bytes = (const uint8_t*)data;

    if (data == NULL || digest_out == NULL) {
        return -1;
    }

    br_sha256_init(&sha_ctx);
    br_sha256_update(&sha_ctx, data_bytes, data_len);
    br_sha256_out(&sha_ctx, digest_out);

    return 0;
}

int verify_signature_by_bearssl(const void* data, size_t data_len,
                                const void* signature, const void* pubkey)
{
    br_ec_public_key pk;
    uint8_t hash[32];
    uint32_t ok;

    if (data == NULL || signature == NULL || pubkey == NULL) {
        return -2;
    }

    compute_sha256_by_bearssl(data, data_len, hash);

    pk.curve = BR_EC_secp256r1;
    pk.q = (unsigned char*)(uintptr_t)pubkey;
    pk.qlen = 65;

    ok = br_ecdsa_i31_vrfy_raw(&br_ec_p256_m31, hash, sizeof(hash), &pk, signature, 64);
    if (ok != 1) {
        return -1; // Signature verification failed
    }
    return 0;
}