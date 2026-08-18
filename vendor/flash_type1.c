/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2014 Renesas Electronics Corporation.
 * Derived from Renesas FIT r_flash_rx (Flash Type 1 / no-FCU).
 */

#include "flash_type1.h"
#include "iodefine.h"
#include <string.h>

#define DF_BASE             (0x00100000u)
#define DF_SIZE             (0x2000u)
#define DF_BLOCK_SIZE       (256u)

#define CF_START            (0xFFF80000u)
#define CF_END              (0xFFFFFFFFu)
#define CF_BLOCK_SIZE       (2048u)
#define CF_MIN_PGM_SIZE     (8u)

/*
 * Read-form to P/E-form address offset (FIT r_flash_common.h, RX23/24 class).
 */
/*
 * From the RX261 manual (fig. 46.1):
 * Read address 0xFFF80000 maps to P/E address 0x00180000.
 * Offset = 0xFFF80000 - 0x00180000.
 */
#define CODEFLASH_ADDR_OFFSET (0xFFE00000u)

#define FENTRYR_READ_MODE   (0xAA00u)
#define FENTRYR_CF_PE_MODE  (0xAA01u)
#define FENTRYR_DF_PE_MODE  (0xAA80u)

#define FCR_WRITE           (0x81u)
#define FCR_ERASE           (0x84u)
#define FCR_BLANKCHECK      (0x83u)
#define FCR_CLEAR           (0x00u)

#define FPMCR_READ_MODE     (0x08u)
#define FPMCR_CF_PE_MODE    (0x02u) /* VARIETY_A (RX140/RX261); not 0x82 */
#define FPMCR_DF_PE_MODE    (0x10u)
#define FPMCR_LVPE          (0x40u)

#define FLASH_TYPE1_OK            (0)
#define FLASH_TYPE1_ERR_PARAM     (-1)
#define FLASH_TYPE1_ERR_TIMEOUT   (-3)
#define FLASH_TYPE1_ERR_FAILURE   (-4)
#define FLASH_TYPE1_ERR_ALIGN     (-5)

#define WAIT_MAX            (0x100000u)
/* FSTATR0 bits: ERERR|PRGERR|BCERR|ILGLERR */
#define FSTATR0_ERR_MASK    (0x13u)
#define FSTATR0_BCERR_MASK  (0x08u)


/*
 * PCKA[5:0] (RX261 HW manual table 46.4).
 * Default 0x2F = 64 MHz. Not (FCLK_MHz - 1).
 */
#ifndef FLASH_TYPE1_PCKA
#define FLASH_TYPE1_PCKA  (0x2Fu)
#endif

/* CPU clock for software delay. One delay loop is 4 cycles (sub + bne + penalty). */
#ifndef FLASH_TYPE1_ICLK_MHZ
#define FLASH_TYPE1_ICLK_MHZ  (64u)
#endif
#define FLASH_TYPE1_DELAY_LOOPS_PER_US  (FLASH_TYPE1_ICLK_MHZ / 4u)

/*
 * Put code that runs in Code Flash P/E mode in this section.
 * Keep the public API and the Data Flash path in .text.
 * (FIT uses R_BSP_ATTRIB_SECTION_CHANGE(P, FRAM).)
 */
#if defined(__GNUC__)
#define FLASH_TYPE1_PE_RAM     __attribute__((section(".text.flash_type1_pe_ram")))
/* Do not inline entry points that the flash API calls. */
#define FLASH_TYPE1_PE_RAM_API __attribute__((section(".text.flash_type1_pe_ram"), noinline))
#else
#define FLASH_TYPE1_PE_RAM
#define FLASH_TYPE1_PE_RAM_API
#endif


static void delay_us(uint32_t us)
{
    uint32_t i = us * FLASH_TYPE1_DELAY_LOOPS_PER_US;
    while (i--) {
        __asm volatile ("");
    }
}

static int is_data_flash(uintptr_t addr)
{
    return (addr >= DF_BASE) && (addr < (DF_BASE + DF_SIZE));
}

static int is_code_flash(uintptr_t addr)
{
    return (addr >= CF_START) && (addr <= CF_END);
}

/* -------------------------------------------------------------------------- */
/* Data Flash path (XIP from Code Flash)                                        */
/* -------------------------------------------------------------------------- */

static void df_write_fpmcr(uint8_t value)
{
    FLASH.FPR = 0xA5u;
    FLASH.FPMCR.BYTE = value;
    FLASH.FPMCR.BYTE = (uint8_t)~value;
    FLASH.FPMCR.BYTE = value;
}

static int df_wait_frdy(void)
{
    for (uint32_t cnt = 0; cnt < WAIT_MAX; ++cnt) {
        if (FLASH.FSTATR1.BIT.FRDY != 0) {
            return FLASH_TYPE1_OK;
        }
    }
    return FLASH_TYPE1_ERR_TIMEOUT;
}

static int df_check_error_and_clear(void)
{
    int ret = FLASH_TYPE1_OK;
    if ((FLASH.FSTATR0.BYTE & FSTATR0_ERR_MASK) != 0) {
        ret = FLASH_TYPE1_ERR_FAILURE;
    }

    FLASH.FCR.BYTE = FCR_CLEAR;
    for (uint32_t cnt = 0; cnt < WAIT_MAX; ++cnt) {
        if (FLASH.FSTATR1.BIT.FRDY == 0) {
            return ret;
        }
    }
    return FLASH_TYPE1_ERR_TIMEOUT;
}

static int enter_df_pe_mode(void)
{
    FLASH.FENTRYR.WORD = FENTRYR_DF_PE_MODE;

    uint32_t cnt = WAIT_MAX;
    while ((FLASH.FENTRYR.WORD & 0x00FFu) != 0x0080u) {
        if (--cnt == 0) {
            return FLASH_TYPE1_ERR_TIMEOUT;
        }
    }

    if (SYSTEM.OPCCR.BIT.OPCM == 0) {
        df_write_fpmcr(FPMCR_DF_PE_MODE);
    } else {
        df_write_fpmcr((uint8_t)(FPMCR_DF_PE_MODE | FPMCR_LVPE));
    }
    FLASH.FISR.BIT.PCKA = (uint8_t)FLASH_TYPE1_PCKA;
    return FLASH_TYPE1_OK;
}

static void enter_df_read_mode(void)
{
    df_write_fpmcr(FPMCR_READ_MODE);
    delay_us(5);

    FLASH.FENTRYR.WORD = FENTRYR_READ_MODE;

    uint32_t cnt = WAIT_MAX;
    while (FLASH.FENTRYR.WORD != 0x0000u) {
        if (--cnt == 0) {
            break;
        }
    }
}

static int df_write_byte(uintptr_t dest, uint8_t data)
{
    const uint32_t pe_addr = 0xFE000000u + ((uint32_t)dest - DF_BASE);

    FLASH.FASR.BIT.EXS = 0;

    FLASH.FSARH = (uint16_t)(pe_addr >> 16);
    FLASH.FSARL = (uint16_t)(pe_addr & 0xFFFFu);

    FLASH.FWB0 = (uint16_t)data;
    FLASH.FWB1 = 0;
    FLASH.FWB2 = 0;
    FLASH.FWB3 = 0;

    FLASH.FCR.BYTE = FCR_WRITE;

    if (df_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }
    return df_check_error_and_clear();
}


static int df_blank_check_block(uintptr_t start)
{
    const uint32_t offset   = (uint32_t)(start & ~(DF_BLOCK_SIZE - 1u)) - DF_BASE;
    const uint32_t pe_start = 0xFE000000u + offset;
    const uint32_t pe_end   = pe_start + DF_BLOCK_SIZE - 1u;

    FLASH.FASR.BIT.EXS = 0;
    FLASH.FSARH = (uint16_t)(pe_start >> 16);
    FLASH.FSARL = (uint16_t)(pe_start & 0xFFFFu);
    FLASH.FEARH = (uint16_t)(pe_end >> 16);
    FLASH.FEARL = (uint16_t)(pe_end & 0xFFFFu);

    FLASH.FCR.BYTE = FCR_BLANKCHECK;

    if (df_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }

    /* BCERR set means the area is not blank. */
    if ((FLASH.FSTATR0.BYTE & FSTATR0_BCERR_MASK) != 0) {
        FLASH.FCR.BYTE = FCR_CLEAR;
        while (FLASH.FSTATR1.BIT.FRDY != 0) {
        }
        return 1;
    }

    return df_check_error_and_clear();
}

static int df_erase_block(uintptr_t start)
{
    const uint32_t offset   = (uint32_t)(start & ~(DF_BLOCK_SIZE - 1u)) - DF_BASE;
    const uint32_t pe_start = 0xFE000000u + offset;
    const uint32_t pe_end   = pe_start + DF_BLOCK_SIZE - 1u;

    FLASH.FASR.BIT.EXS = 0;

    FLASH.FSARH = (uint16_t)(pe_start >> 16);
    FLASH.FSARL = (uint16_t)(pe_start & 0xFFFFu);
    FLASH.FEARH = (uint16_t)(pe_end   >> 16);
    FLASH.FEARL = (uint16_t)(pe_end   & 0xFFFFu);

    FLASH.FCR.BYTE = FCR_ERASE;

    if (df_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }
    return df_check_error_and_clear();
}

static int df_write(uintptr_t address, const uint8_t *src, size_t size)
{
    int ret = enter_df_pe_mode();
    while (ret == FLASH_TYPE1_OK && size > 0) {
        ret = df_write_byte(address, *src);
        address++;
        src++;
        size--;
    }
    enter_df_read_mode();
    return ret;
}

static int df_erase(uintptr_t address)
{
    int ret = enter_df_pe_mode();
    if (ret == FLASH_TYPE1_OK) {
        ret = df_blank_check_block(address);
        /* Erase only if the block is not blank. */
        if (ret == 1) {
            ret = df_erase_block(address);
        }
    }
    enter_df_read_mode();
    return ret;
}

/* -------------------------------------------------------------------------- */
/* Code Flash path (must run from RAM; ROM fetch disabled in CF P/E mode)     */
/* -------------------------------------------------------------------------- */

FLASH_TYPE1_PE_RAM
static void cf_delay_us(uint32_t us)
{
    uint32_t i = us * FLASH_TYPE1_DELAY_LOOPS_PER_US;
    while (i--) {
        __asm volatile ("");
    }
}

FLASH_TYPE1_PE_RAM
static void cf_write_fpmcr(uint8_t value)
{
    FLASH.FPR = 0xA5u;
    FLASH.FPMCR.BYTE = value;
    FLASH.FPMCR.BYTE = (uint8_t)~value;
    FLASH.FPMCR.BYTE = value;
}

FLASH_TYPE1_PE_RAM
static int cf_wait_frdy(void)
{
    for (uint32_t cnt = 0; cnt < WAIT_MAX; ++cnt) {
        if (FLASH.FSTATR1.BIT.FRDY != 0) {
            return FLASH_TYPE1_OK;
        }
    }
    return FLASH_TYPE1_ERR_TIMEOUT;
}

FLASH_TYPE1_PE_RAM
static int cf_check_error_and_clear(void)
{
    int ret = FLASH_TYPE1_OK;
    if ((FLASH.FSTATR0.BYTE & FSTATR0_ERR_MASK) != 0) {
        ret = FLASH_TYPE1_ERR_FAILURE;
    }

    FLASH.FCR.BYTE = FCR_CLEAR;
    for (uint32_t cnt = 0; cnt < WAIT_MAX; ++cnt) {
        if (FLASH.FSTATR1.BIT.FRDY == 0) {
            return ret;
        }
    }
    return FLASH_TYPE1_ERR_TIMEOUT;
}

FLASH_TYPE1_PE_RAM
static int enter_cf_pe_mode(void)
{
    /* r_flash_nofcu.c flash_cf_pe_mode_enter (FLASH_TYPE_VARIETY_A) */
    FLASH.FENTRYR.WORD = FENTRYR_CF_PE_MODE;
    cf_write_fpmcr(FPMCR_CF_PE_MODE);
    FLASH.FISR.BIT.PCKA = (uint8_t)FLASH_TYPE1_PCKA;
    return FLASH_TYPE1_OK;
}




FLASH_TYPE1_PE_RAM
static void enter_cf_read_mode(void)
{
    /* r_flash_nofcu.c flash_cf_read_mode_enter (FLASH_TYPE_VARIETY_A: no discharge) */
    cf_write_fpmcr(FPMCR_READ_MODE);
    cf_delay_us(5);

    FLASH.FENTRYR.WORD = FENTRYR_READ_MODE;
    while (FLASH.FENTRYR.WORD != 0x0000u) {
    }
}





FLASH_TYPE1_PE_RAM
static int cf_write_8byte(uintptr_t dest, const uint8_t *src)
{
    /* FIT: read address - CODEFLASH_ADDR_OFFSET */
    const uint32_t pe_addr = (uint32_t)dest - CODEFLASH_ADDR_OFFSET;

    FLASH.FASR.BIT.EXS = 0;

    /* FIT MCU_RX23_ALL / RX24 path: full high halfword */
    FLASH.FSARH = (uint16_t)(pe_addr >> 16);
    FLASH.FSARL = (uint16_t)(pe_addr & 0xFFFFu);

    FLASH.FWB0 = (uint16_t)(src[0] | (src[1] << 8));
    FLASH.FWB1 = (uint16_t)(src[2] | (src[3] << 8));
    FLASH.FWB2 = (uint16_t)(src[4] | (src[5] << 8));
    FLASH.FWB3 = (uint16_t)(src[6] | (src[7] << 8));

    FLASH.FCR.BYTE = FCR_WRITE;

    if (cf_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }
    return cf_check_error_and_clear();
}


FLASH_TYPE1_PE_RAM
static int cf_blank_check_block(uintptr_t start)
{
    const uint32_t pe_start =
        (uint32_t)(start & ~(CF_BLOCK_SIZE - 1u)) - CODEFLASH_ADDR_OFFSET;
    const uint32_t pe_end = pe_start + CF_BLOCK_SIZE - 1u;

    FLASH.FASR.BIT.EXS = 0;
    /* Align the address to 8 bytes (FIT does the same). */
    FLASH.FSARH = (uint16_t)(pe_start >> 16);
    FLASH.FSARL = (uint16_t)(pe_start & 0xFFF8u);
    FLASH.FEARH = (uint16_t)(pe_end >> 16);
    FLASH.FEARL = (uint16_t)(pe_end & 0xFFF8u);

    FLASH.FCR.BYTE = FCR_BLANKCHECK;

    if (cf_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }

    /* BCERR set means the area is not blank. */
    if ((FLASH.FSTATR0.BYTE & FSTATR0_BCERR_MASK) != 0) {
        FLASH.FCR.BYTE = FCR_CLEAR;
        while (FLASH.FSTATR1.BIT.FRDY != 0) {
        }
        return 1;
    }

    return cf_check_error_and_clear();
}

FLASH_TYPE1_PE_RAM
static int cf_erase_block(uintptr_t start)
{
    /* FIT R_CF_Erase: convert read-form addresses to P/E-form */
    const uint32_t pe_start =
        (uint32_t)(start & ~(CF_BLOCK_SIZE - 1u)) - CODEFLASH_ADDR_OFFSET;
    const uint32_t pe_end = pe_start + CF_BLOCK_SIZE - 1u;

    FLASH.FASR.BIT.EXS = 0;

    FLASH.FSARH = (uint16_t)(pe_start >> 16);
    FLASH.FSARL = (uint16_t)(pe_start & 0xFFFFu);
    FLASH.FEARH = (uint16_t)(pe_end   >> 16);
    FLASH.FEARL = (uint16_t)(pe_end   & 0xFFFFu);

    FLASH.FCR.BYTE = FCR_ERASE;

    if (cf_wait_frdy() != FLASH_TYPE1_OK) {
        return FLASH_TYPE1_ERR_TIMEOUT;
    }
    return cf_check_error_and_clear();
}

/*
 * Call this fromflash_type1_write() in flash.
 * The noinline attribute keeps the body in .text.flash_type1_pe_ram.
 */
FLASH_TYPE1_PE_RAM_API
static int cf_write(uintptr_t address, const uint8_t *src, size_t size)
{
    int ret = enter_cf_pe_mode();
    while (ret == FLASH_TYPE1_OK && size >= CF_MIN_PGM_SIZE) {
        ret = cf_write_8byte(address, src);
        address += CF_MIN_PGM_SIZE;
        src     += CF_MIN_PGM_SIZE;
        size    -= CF_MIN_PGM_SIZE;
    }
    enter_cf_read_mode();
    return ret;
}

FLASH_TYPE1_PE_RAM_API
static int cf_erase(uintptr_t address)
{
    int ret = enter_cf_pe_mode();
    if (ret == FLASH_TYPE1_OK) {
        ret = cf_blank_check_block(address);
        /* Erase only if the block is not blank. */
        if (ret == 1) {
            ret = cf_erase_block(address);
        }
    }
    enter_cf_read_mode();
    return ret;
}

/* -------------------------------------------------------------------------- */
/* Public API (flash-resident; CF work is delegated to RAM functions)         */
/* -------------------------------------------------------------------------- */

void flash_type1_init(void)
{
    FLASH.DFLCTL.BIT.DFLEN = 1;
    while (FLASH.DFLCTL.BIT.DFLEN == 0) {
    }
    delay_us(5);


    enter_df_read_mode();
}

int flash_type1_write(uintptr_t address, const void *data, size_t size)
{
    if (data == NULL || size == 0) {
        return FLASH_TYPE1_ERR_PARAM;
    }

    const uint8_t *src = (const uint8_t *)data;

    if (is_data_flash(address)) {
        if ((address + size) > (DF_BASE + DF_SIZE)) {
            return FLASH_TYPE1_ERR_PARAM;
        }
        return df_write(address, src, size);
    }

    if (is_code_flash(address)) {
        if ((address & (CF_MIN_PGM_SIZE - 1u)) != 0 ||
            (size & (CF_MIN_PGM_SIZE - 1u)) != 0) {
            return FLASH_TYPE1_ERR_ALIGN;
        }
        return cf_write(address, src, size);
    }

    return FLASH_TYPE1_ERR_PARAM;
}

int flash_type1_erase_sector(uintptr_t address)
{
    if (is_data_flash(address)) {
        return df_erase(address);
    }

    if (is_code_flash(address)) {
        return cf_erase(address);
    }

    return FLASH_TYPE1_ERR_PARAM;
}
