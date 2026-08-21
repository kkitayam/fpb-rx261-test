#include "flash_type1.h"
#include <stdint.h>
#include <string.h>

#define DF_TEST_ADDR    (0x00100000u)
#define DF_TEST_SIZE    (16u)

/* 2 KB block just under BOOT_ORIGIN (0xFFFF0000). */
#define CF_TEST_ADDR    (0xFFFEF800u)
#define CF_TEST_SIZE    (16u)   /* multiple of 8 */

// Returns 0 on success.
// -1 erase failed, -2 post-erase not 0xFF, -3 write failed, -4 verify mismatch.
int test_data_flash(void)
{
    uint8_t write_buf[DF_TEST_SIZE];
    uint8_t read_buf[DF_TEST_SIZE];
    uint32_t i;
    int ret;

    for (i = 0; i < DF_TEST_SIZE; i++) {
        write_buf[i] = (uint8_t)(0xA0u + i);
    }

    ret = flash_type1_erase_sector(DF_TEST_ADDR);
    if (ret != 0) {
        return -1;
    }

    {
        const uint8_t *p = (const uint8_t *)DF_TEST_ADDR;
        for (i = 0; i < DF_TEST_SIZE; i++) {
            if (p[i] != 0xFFu) {
                return -2;
            }
        }
    }

    ret = flash_type1_write(DF_TEST_ADDR, write_buf, DF_TEST_SIZE);
    if (ret != 0) {
        return -3;
    }

    memcpy(read_buf, (const void *)DF_TEST_ADDR, DF_TEST_SIZE);

    if (memcmp(write_buf, read_buf, DF_TEST_SIZE) != 0) {
        return -4;
    }

    return 0;
}

/* Returns 0 on success.
 * -1 erase failed, -2 post-erase not 0xFF, -3 write failed, -4 verify mismatch.
 */
int test_code_flash(void)
{
    uint8_t write_buf[CF_TEST_SIZE];
    uint8_t read_buf[CF_TEST_SIZE];
    uint32_t i;
    int ret;

    for (i = 0; i < CF_TEST_SIZE; i++) {
        write_buf[i] = (uint8_t)(0x50u + i);
    }

    ret = flash_type1_erase_sector(CF_TEST_ADDR);
    if (ret != 0) {
        return -1;
    }

    {
        const uint8_t *p = (const uint8_t *)CF_TEST_ADDR;
        for (i = 0; i < CF_TEST_SIZE; i++) {
            if (p[i] != 0xFFu) {
                return -2;
            }
        }
    }

    ret = flash_type1_write(CF_TEST_ADDR, write_buf, CF_TEST_SIZE);
    if (ret != 0) {
        return -3;
    }

    memcpy(read_buf, (const void *)CF_TEST_ADDR, CF_TEST_SIZE);

    if (memcmp(write_buf, read_buf, CF_TEST_SIZE) != 0) {
        return -4;
    }

    return 0;
}