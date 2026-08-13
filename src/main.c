#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include "uart.h"
#include "rsip_ecdsa_p256_sha256.h"

extern void gptw_start_freerun(void);
extern uint32_t gptw_get_count(void);
extern int compute_sha256_by_bearssl(const void* data, size_t data_len, uint8_t digest_out[32]);
extern int verify_signature_by_bearssl(const void* data, size_t data_len,
                                const void* signature, const void* pubkey);

static const uint8_t test_pubkey[] = {
    0x04, 0x2e, 0x2a, 0xd1, 0x1c, 0xb4, 0x6b, 0xb9,
    0x1b, 0x94, 0xf3, 0x52, 0xe3, 0x4c, 0xcd, 0xde,
    0x07, 0x65, 0xb8, 0x2b, 0xb2, 0x9b, 0x21, 0x5e,
    0x9d, 0xd6, 0x42, 0x9c, 0x2b, 0xbc, 0x1e, 0xd1,
    0x96, 0xd7, 0x0c, 0xad, 0xa7, 0xb7, 0xb1, 0x0d,
    0x11, 0x28, 0x07, 0xe7, 0xbd, 0x0f, 0x77, 0x26,
    0xbd, 0x21, 0x8d, 0xb9, 0xc5, 0x5c, 0x75, 0x90,
    0x6d, 0x38, 0xfb, 0xfd, 0x5f, 0xaa, 0x97, 0xab,
    0xeb
};

/*
 * Valid ECDSA P-256 signature (raw r||s, 64 bytes) over
 * "Hello, Mebuki ECDSA!" using SHA-256 and the test private key.
 */
static const uint8_t test_signature[] = {
    0x15, 0x58, 0xde, 0x2a, 0x77, 0x68, 0xdc, 0x7c,
    0xa2, 0xab, 0x5f, 0x9f, 0x77, 0xec, 0x7d, 0x14,
    0xf4, 0x44, 0x23, 0x87, 0xd8, 0xb1, 0x4c, 0x3e,
    0x8d, 0x70, 0x35, 0x22, 0x7e, 0x32, 0x0e, 0x39,
    0x6d, 0x69, 0x30, 0x73, 0x7d, 0x17, 0xd6, 0xca,
    0xb5, 0xd2, 0xf8, 0x55, 0x81, 0xb8, 0xa6, 0x0d,
    0x2f, 0x78, 0x1e, 0x38, 0x7a, 0xfb, 0x1e, 0x14,
    0x1a, 0x59, 0x4c, 0x9b, 0x74, 0x83, 0x01, 0x15
};

static const uint8_t test_data[] = "Hello, Mebuki ECDSA!";
static const size_t test_data_len = sizeof(test_data) - 1;

int test_compute_hash_known_vector(void)
{
    int err;
    const static uint8_t input[] = "abc";
    /* SHA-256("abc") */
    const static uint8_t expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t computed[sizeof(expected)];
    err = rsip_sha256_compute(input, 3, computed);
    if (err) return err;
    err = memcmp(expected, computed, sizeof(expected));
    return err ? -1 : 0;
}

int test_verify_known_sig(void)
{
    int err;
    uint8_t digest[32];
    err = rsip_sha256_compute(test_data, test_data_len, digest);
    if (err) return err;
    err = rsip_ecdsa_p256_verify_hash(digest, test_signature, test_pubkey);
    return err;
}

static void uart_put_uint(const char* s, uint32_t value, bool negative)
{
    char buf[32]; /* int32_t max is 11 digits + sign + null terminator */
    char *p = buf + sizeof(buf) - 1;
    *p = '\0';

    do {
        *--p = '0' + (value % 10);
        value /= 10;
    } while (value != 0);

    if (negative) {
        *--p = '-';
    }

    uart_puts(s);
    uart_puts(p);
    uart_putc('\n');
}

void uart_put_digit(const char* s, uint32_t value)
{
    uart_put_uint(s, value, false);
}

void uart_put_int(const char* s, int value)
{
    bool negative = value < 0;
    unsigned u = negative ? -(unsigned)value : (unsigned)value;
    uart_put_uint(s, u, negative);
}

void bench(void)
{
    int err;
    static const uint8_t input[] = "kjda^1kbjx/qe@gfs[]rold@2[4529f&%'(=;bdafd;skj32.)]dlakjdflajdsflajsdflkajsdflajsdlfjasldfjalsdkfjalsdkjfalsdkfjaldskfjaldskjflasdjflaksjdflkasjdflajsdlfkjasdlkfj43518410384132741923871932741932791273491732497123947193284712934719034710932749127349alsdj";
    uint32_t last, cur;
    uint8_t computed0[32], computed1[32];

    last = gptw_get_count();
    err = rsip_sha256_compute(input, sizeof(input), computed0);
    cur = gptw_get_count();
    uart_put_digit("RSIP: ", cur - last);
    if (err) { uart_put_int("fail rsip_sha256_compute: ", err); return; }

    last = gptw_get_count();
    err = compute_sha256_by_bearssl(input, sizeof(input), computed1);
    cur = gptw_get_count();
    uart_put_digit("BearSSL: ", cur - last);
    if (err) { uart_put_int("fail compute_sha256_by_bearssl: ", err); return; }

    if (memcmp(computed0, computed1, sizeof(computed0)) != 0) {
        uart_puts("fail: computed hash mismatch\n");
        return;
    }
}

void bench2(void)
{
    int err;
    uint8_t digest[32];
    uint32_t last, cur;

    last = gptw_get_count();
    err = rsip_sha256_compute(test_data, test_data_len, digest);
    if (err) { uart_put_int("fail rsip_sha256_compute: ", err); return; }
    err = rsip_ecdsa_p256_verify_hash(digest, test_signature, test_pubkey);
    if (err) { uart_put_int("fail rsip_ecdsa_p256_verify_hash: ", err); return; }
    cur = gptw_get_count();
    uart_put_digit("ECDSA P-256 verify: ", cur - last);

    last = gptw_get_count();
    err = verify_signature_by_bearssl(test_data, test_data_len, test_signature, test_pubkey);
    if (err) { uart_put_int("fail verify_signature_by_bearssl: ", err); return; }
    cur = gptw_get_count();
    uart_put_digit("ECDSA P-256 verify by BearSSL: ", cur - last);
}

int main(void)
{
    uint32_t last, cur;
    uart_init();
    uart_puts("Hello UART\n");

#if 1
    gptw_start_freerun();

    last = gptw_get_count();
    uart_put_digit("Last count: ", last);

    cur = gptw_get_count();
    uart_put_digit("Delta count: ", cur - last);
    last = cur;
    cur = gptw_get_count();
    uart_put_digit("Delta count: ", cur - last);
#endif

    int err;
    err = rsip_hw_init();
    if (err) { uart_put_int("fail rsip_hw_init: ", err); return -1; }
    uart_puts("pass rsip_hw_init\n");

    last = gptw_get_count();
    err = rsip_sha256_selftest();
    cur = gptw_get_count();
    uart_put_digit("selftest: ", cur - last);
    if (err) { uart_put_int("fail sha256 selftest: ", err); return -1; }
    uart_puts("pass sha256 selftest\n");

    last = gptw_get_count();
    err = test_compute_hash_known_vector();
    cur = gptw_get_count();
    uart_put_digit("known vector: ", cur - last);
    if (err) { uart_put_int("fail known vector: ", err); return -1; }
    uart_puts("pass known vector\n");

    bench();

    /** Self-test with RFC 6979 A.2.5 ("sample"). 0 = pass. */
    last = gptw_get_count();
    err = rsip_ecdsa_p256_selftest();
    cur = gptw_get_count();
    uart_put_digit("ecdsa p256 selftest: ", cur - last);
    if (err) { uart_put_int("fail ecdsa p256 selftest: ", err); return -1; }
    uart_puts("pass ecdsa p256 selftest\n");

    last = gptw_get_count();
    err = test_verify_known_sig();
    cur = gptw_get_count();
    uart_put_digit("verify known sig: ", cur - last);
    if (err) { uart_put_int("fail verify known sig: ", err); return -1; }
    uart_puts("pass verify known sig\n");

    bench2();

    return 0;
}
