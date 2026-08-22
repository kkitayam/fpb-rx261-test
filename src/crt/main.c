#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "uart.h"
#include "rsip_ecdsa_p256_sha256.h"

extern void gptw_start_freerun(void);
extern uint32_t gptw_get_count(void);
extern int compute_sha256_by_bearssl(const void* data, size_t data_len, uint8_t digest_out[32]);
extern int verify_signature_by_bearssl(const void* data, size_t data_len,
                                const void* signature, const void* pubkey);
extern int test_verify_known_sig(void);
extern int test_compute_hash_known_vector(void);
extern int test_data_flash(void);
extern int test_code_flash(void);
extern void bench_sha256(void);
extern void bench_ecdsa(void);
extern void flash_type1_init(void);


void uart_put_digit(const char* s, uint32_t value)
{
    printf("%s%lu\n", s, value);
}

void uart_put_int(const char* s, int value)
{
    printf("%s%d\n", s, value);
}

int main(void)
{
    uint32_t last, cur;
    uart_init();
    uart_puts("Hello UART\n");
    printf("Hello UART\n");

#if 1
    gptw_start_freerun();

    last = gptw_get_count();
    printf("Last count: %lu\n", last);

    cur = gptw_get_count();
    printf("Delta count: %lu\n", cur - last);
    last = cur;
    cur = gptw_get_count();
    printf("Delta count: %lu\n", cur - last);
#endif

    int err;
    err = rsip_hw_init();
    if (err) { printf("fail rsip_hw_init: %d\n", err); return -1; }
    printf("pass rsip_hw_init\n");

    last = gptw_get_count();
    err = rsip_sha256_selftest();
    cur = gptw_get_count();
    printf("selftest: %lu\n", cur - last);
    if (err) { printf("fail sha256 selftest: %d\n", err); return -1; }
    printf("pass sha256 selftest\n");

    last = gptw_get_count();
    err = test_compute_hash_known_vector();
    cur = gptw_get_count();
    printf("known vector: %lu\n", cur - last);
    if (err) { printf("fail known vector: %d\n", err); return -1; }
    printf("pass known vector\n");

    bench_sha256();

    /** Self-test with RFC 6979 A.2.5 ("sample"). 0 = pass. */
    last = gptw_get_count();
    err = rsip_ecdsa_p256_selftest();
    cur = gptw_get_count();
    printf("ecdsa p256 selftest: %lu\n", cur - last);
    if (err) { printf("fail ecdsa p256 selftest: %d\n", err); return -1; }
    printf("pass ecdsa p256 selftest\n");

    last = gptw_get_count();
    err = test_verify_known_sig();
    cur = gptw_get_count();
    printf("verify known sig: %lu\n", cur - last);
    if (err) { printf("fail verify known sig: %d\n", err); return -1; }
    printf("pass verify known sig\n");

    bench_ecdsa();

    flash_type1_init();

    err = test_data_flash();
    if (err) { printf("fail test_data_flash: %d\n", err); return -1; }
    printf("pass test_data_flash\n");

    err = test_code_flash();
    if (err) { printf("fail test_code_flash: %d\n", err); return -1; }
    printf("pass test_code_flash\n");

    return 0;
}
