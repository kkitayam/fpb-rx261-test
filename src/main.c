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
extern int test_verify_known_sig(void);
extern int test_compute_hash_known_vector(void);
extern int test_data_flash(void);
extern int test_code_flash(void);
extern void bench_sha256(void);
extern void bench_ecdsa(void);
extern void hal_flash_init(void);

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

    bench_sha256();

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

    bench_ecdsa();

    hal_flash_init();    

    err = test_data_flash();
    if (err) { uart_put_int("fail test_data_flash: ", err); return -1; }
    uart_puts("pass test_data_flash\n");

    err = test_code_flash();
    if (err) { uart_put_int("fail test_code_flash: ", err); return -1; }
    uart_puts("pass test_code_flash\n");

    return 0;
}
