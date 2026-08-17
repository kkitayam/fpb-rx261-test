/*
 * Copyright (c) 2025 Renesas Electronics Corporation and/or its affiliates
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is a derived work from Renesas r_rsip_cm_rx (rx-driver-package).
 * Original copyright is retained under the BSD-3-Clause license terms.
 *
 * Source map (primitive/rx261 unless noted):
 *   SHA: p72, p00, p81, p82, p40, func100-103
 *   ECDSA: pf1, func070/071/073, DomainParams.c (__LIT)
 *
 * rsip_ecdsa_p256_sha256.c
 * Bootloader driver: polling only, no PSA/mbedTLS link.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "iodefine.h"
#include "rsip_ecdsa_p256_sha256.h"

typedef int fsp_err_t;
#define FSP_SUCCESS                         (0)
#define FSP_ERR_CRYPTO_SCE_FAIL             (-1)
#define FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT (-2)
#define FSP_ERR_CRYPTO_SCE_RETRY             (-3)

/* Distinct codes so the caller can see which init step failed without a debugger. */
#define RSIP_ERR_SELFCHECK1                 (-10)
#define RSIP_ERR_SELFCHECK2                 (-11)
#define RSIP_ERR_HUK                        (-12)
#define RSIP_ERR_SC1_VERSION                (-101)
#define RSIP_ERR_SC1_BUSY                   (-102)
#define RSIP_ERR_SC1_CRYPTO                 (-103)

/* Needs board iodefine symbols SYSTEM and MSTP(RSIP). Override if the BSP names differ. */
#ifndef RSIP_MSTP_CLEAR
#define RSIP_MSTP_CLEAR() do { \
    SYSTEM.PRCR.WORD = 0xA502; MSTP(RSIP) = 0; SYSTEM.PRCR.WORD = 0xA500; } while (0)
#endif
#ifndef RSIP_MSTP_SET
#define RSIP_MSTP_SET() do { \
    SYSTEM.PRCR.WORD = 0xA502; MSTP(RSIP) = 1; SYSTEM.PRCR.WORD = 0xA500; } while (0)
#endif

#define RSIP_CURVE_TYPE_NIST_P256  (0u)

#define R_RSIP_LITTLE_ENDIAN_MODE  (0x00010001u)

/* Offsets match r_rsip_rx261_iodefine.h. Base is the CM RSIP window on RX261. */
#define SCE_BASE  (0x0008BA00u)

#define REG_0000H  0x000u
#define REG_0004H  0x004u
#define REG_0008H  0x008u
#define REG_000CH  0x00Cu
#define REG_0010H  0x010u
#define REG_0014H  0x014u
#define REG_0018H  0x018u
#define REG_001CH  0x01Cu
#define REG_0020H  0x020u
#define REG_0024H  0x024u
#define REG_002CH  0x02Cu
#define REG_0038H  0x038u
#define REG_0040H  0x040u
#define REG_0044H  0x044u
#define REG_0048H  0x048u
#define REG_004CH  0x04Cu
#define REG_0068H  0x068u
#define REG_006CH  0x06Cu
#define REG_0070H  0x070u
#define REG_0078H  0x078u
#define REG_008CH  0x08Cu
#define REG_0090H  0x090u
#define REG_0094H  0x094u
#define REG_009CH  0x09Cu
#define REG_00A0H  0x0A0u

#define REG_00A4H  0x0A4u
#define REG_00A8H  0x0A8u
#define REG_00ACH  0x0ACu
#define REG_00B4H  0x0B4u
#define REG_00B8H  0x0B8u
#define REG_00B0H  0x0B0u
#define REG_00C0H  0x0C0u
#define REG_00C4H  0x0C4u
#define REG_00C8H  0x0C8u
#define REG_00D0H  0x0D0u
#define REG_00D4H  0x0D4u
#define REG_00D8H  0x0D8u
#define REG_00E0H  0x0E0u
#define REG_00E4H  0x0E4u
#define REG_00E8H  0x0E8u
#define REG_00F0H  0x0F0u
#define REG_00F4H  0x0F4u
#define REG_00F8H  0x0F8u

#define SCE_REG(off)  (*(volatile uint32_t *)((uintptr_t)SCE_BASE + (uintptr_t)(off)))

#define WR1_PROG(regName, value)   do { SCE_REG(regName) = (uint32_t)(value); } while (0)
#define RD1_PROG(regName)          (SCE_REG(regName))
#define RD1_MASK(regName, m)       (SCE_REG(regName) & (uint32_t)(m))
#define CHCK_STS(regName, bitPos, value) \
    (((SCE_REG(regName) >> (bitPos)) & 1u) == (uint32_t)(value))
#define WAIT_STS(regName, bitPos, value) \
    do { while (!CHCK_STS(regName, bitPos, value)) { } } while (0)

#define WR1_ADDR(regName, addr)    do { SCE_REG(regName) = *((const uint32_t *)(addr)); } while (0)

#define WR4_PROG(regName, v0, v1, v2, v3) do { \
    WR1_PROG(regName, v0); WR1_PROG(regName, v1); \
    WR1_PROG(regName, v2); WR1_PROG(regName, v3); \
} while (0)

#define WR4_ADDR(regName, addr) do { \
    const uint32_t *_p = (const uint32_t *)(addr); \
    WR1_ADDR(regName, _p + 0); WR1_ADDR(regName, _p + 1); \
    WR1_ADDR(regName, _p + 2); WR1_ADDR(regName, _p + 3); \
} while (0)

#define WR8_ADDR(regName, addr) do { \
    const uint32_t *_p = (const uint32_t *)(addr); \
    WR1_ADDR(regName, _p + 0); WR1_ADDR(regName, _p + 1); \
    WR1_ADDR(regName, _p + 2); WR1_ADDR(regName, _p + 3); \
    WR1_ADDR(regName, _p + 4); WR1_ADDR(regName, _p + 5); \
    WR1_ADDR(regName, _p + 6); WR1_ADDR(regName, _p + 7); \
} while (0)

#define WR16_ADDR(regName, addr) do { \
    const uint32_t *_p = (const uint32_t *)(addr); \
    unsigned _i; \
    for (_i = 0; _i < 16u; _i++) { WR1_ADDR(regName, _p + _i); } \
} while (0)

#define RD8_ADDR(regName, addr) do { \
    uint32_t *_p = (uint32_t *)(addr); \
    unsigned _i; \
    for (_i = 0; _i < 8u; _i++) { _p[_i] = SCE_REG(regName); } \
} while (0)

/* Prefer the RX reverse-long instruction when the compiler can emit it. */
#if defined(__GNUC__)
#define change_endian_long(a)  __builtin_bswap32(a)
#else
static uint32_t change_endian_long(uint32_t a)
{
    return ((a & 0x000000FFu) << 24) |
           ((a & 0x0000FF00u) <<  8) |
           ((a & 0x00FF0000u) >>  8) |
           ((a & 0xFF000000u) >> 24);
}
#endif

static void HW_SCE_p_func100(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4)
{
    WR1_PROG(REG_00D0H, 0x0a0701f5U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_PROG(REG_002CH,
             change_endian_long(ARG1), change_endian_long(ARG2),
             change_endian_long(ARG3), change_endian_long(ARG4));
    WAIT_STS(REG_00C8H, 16, 0);
}

static void HW_SCE_p_func101(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4)
{
    WR1_PROG(REG_00D0H, 0x0a0701e5U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_PROG(REG_002CH,
             change_endian_long(ARG1), change_endian_long(ARG2),
             change_endian_long(ARG3), change_endian_long(ARG4));
    WAIT_STS(REG_00C8H, 17, 0);
}

static void HW_SCE_p_func102(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4)
{
    WR1_PROG(REG_00D0H, 0x0a0701d5U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_PROG(REG_002CH,
             change_endian_long(ARG1), change_endian_long(ARG2),
             change_endian_long(ARG3), change_endian_long(ARG4));
}

static void HW_SCE_p_func103(void)
{
    WR1_PROG(REG_0014H, 0x000002a1U);
    WR1_PROG(REG_00D0H, 0x07330c04U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

    WR1_PROG(REG_00D0H, 0x07330d04U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

    WR1_PROG(REG_00D0H, 0x07330d04U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

    WR1_PROG(REG_00D0H, 0x08000065U);
    WR1_PROG(REG_0000H, 0x00410011U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_0014H, 0x000000a1U);
    WR1_PROG(REG_00D0H, 0x06330074U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

    WR1_PROG(REG_00D0H, 0x080000b5U);
    WR1_PROG(REG_0000H, 0x00410011U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);
}

static void HW_SCE_SoftwareResetSub(void)
{
    WR1_PROG(REG_000CH, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);
}

/* From hw_sce_p_p81.c. Keep magic constants as in FIT. */
static fsp_err_t HW_SCE_SelfCheck1Sub(void)
{
    WR1_PROG(REG_008CH, 0x00000001U);
    WAIT_STS(REG_008CH, 1, 0);

    if (RD1_MASK(REG_0090H, 0xFFFFFFFFU) != 0x0009F7C3U) {
        return (fsp_err_t)RSIP_ERR_SC1_VERSION;
    }

    WR1_PROG(REG_000CH, 0x38c60eedU);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0048H, 0x00000000U);

    WR1_PROG(REG_0008H, 0x00000001U);
    WR1_PROG(REG_0010H, 0x00001601U);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (RD1_MASK(REG_006CH, 0x00000017U) != 0) {
        return (fsp_err_t)RSIP_ERR_SC1_BUSY;
    }

    WR1_PROG(REG_00C0H, 0x00000001U);
    WR1_PROG(REG_00E0H, 0x00000001U);
    WR1_PROG(REG_00F0H, 0x00000001U);

    WR1_PROG(REG_0070H, 0x00818001U);
    WR1_PROG(REG_0078H, 0x00000d00U);

    WR1_PROG(REG_00C4H, 0x00008004U);

    WR1_PROG(REG_0014H, 0x000003a1U);
    HW_SCE_p_func101(change_endian_long(0x0bba5221U), change_endian_long(0x25146762U),
                     change_endian_long(0x6e96356aU), change_endian_long(0x33468a16U));
    WR1_PROG(REG_00C4H, 0x00000000U);

    WR1_PROG(REG_0014H, 0x000003a1U);
    WR1_PROG(REG_00D0H, 0x0a0700f5U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_PROG(REG_002CH, 0x4f663c12U, 0xd7a41a5dU, 0x7d9d5f07U, 0x3863ca31U);

    HW_SCE_p_func101(change_endian_long(0x28f72f0bU), change_endian_long(0xbe71c42bU),
                     change_endian_long(0xd7d0be43U), change_endian_long(0xb1ba802cU));

    HW_SCE_p_func100(change_endian_long(0x0ab49e02U), change_endian_long(0xb1441f77U),
                     change_endian_long(0x0ed9b912U), change_endian_long(0xee5665fbU));

    WR1_PROG(REG_0008H, 0x00020000U);

    if (CHCK_STS(REG_0020H, 13, 0)) {
        WR1_PROG(REG_006CH, 0x00000020U);
        return (fsp_err_t)RSIP_ERR_SC1_CRYPTO;
    }

    WR1_PROG(REG_0038H, 0x000000F1U);
    WR1_PROG(REG_0078H, 0x00000220U);

    HW_SCE_p_func102(change_endian_long(0xd03e8458U), change_endian_long(0xda950502U),
                     change_endian_long(0xc7128abdU), change_endian_long(0x9ced6237U));
    WR1_PROG(REG_006CH, 0x00000040U);
    WAIT_STS(REG_0020H, 12, 0);

    return FSP_SUCCESS;
}

/* From hw_sce_p_p82.c */
static fsp_err_t HW_SCE_SelfCheck2Sub (void)
{
    uint32_t iLoop = 0U;
    uint32_t jLoop = 0U;

    if (RD1_MASK(REG_006CH, 0x00000017U) != 0)
    {
        return FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT;
    }

    WR1_PROG(REG_0070H, 0x00820001U);
    WR1_PROG(REG_004CH, 0x00000000U);

    WR1_PROG(REG_0014H, 0x000000a1U);
    WR1_PROG(REG_00D0H, 0x0b0700c4U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x013e68caU));

    WR1_PROG(REG_0014H, 0x000000a1U);
    WR1_PROG(REG_00D0H, 0x08000074U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

    WR1_PROG(REG_0094H, 0x3000a820U);
    WR1_PROG(REG_0094H, 0x00000003U);
    WR1_PROG(REG_0094H, 0x00010020U);
    WR1_PROG(REG_0094H, 0x00000821U);
    WR1_PROG(REG_0094H, 0x00000080U);

    WAIT_STS(REG_00E8H, 0, 0);

    HW_SCE_p_func100(0xab0c0f66U, 0x9091e0c6U, 0x316e51e0U, 0x5e185324U);
    WR1_PROG(REG_0094H, 0x00007c01U);
    WR1_PROG(REG_0040H, 0x00600000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (RD1_MASK(REG_0044H, 0x0000ffffU) == 0x00000000U)
    {
        WAIT_STS(REG_00E8H, 0, 0);
        WR1_PROG(REG_00E4H, 0x00200003U);

        HW_SCE_p_func101(0x2f998b08U, 0x388910f9U, 0xbd6bc19eU, 0xaa828a85U);
    }
    else if (RD1_MASK(REG_0044H, 0x0000ffffU) == 0x00000001U)
    {
        WAIT_STS(REG_00E8H, 0, 0);
        WR1_PROG(REG_00E4H, 0x00200001U);

        HW_SCE_p_func101(0xf477b2a8U, 0x03dc2583U, 0xcad40fefU, 0x0a833e8bU);
    }
    else if (RD1_MASK(REG_0044H, 0x0000ffffU) == 0x00000002U)
    {
        WAIT_STS(REG_00E8H, 0, 0);
        WR1_PROG(REG_00E4H, 0x00200002U);

        HW_SCE_p_func101(0x86d7d867U, 0x0963f90cU, 0x00a17e7cU, 0x36083de1U);
    }

    WR1_PROG(REG_00D0H, 0x08000044U);
    WR1_PROG(REG_009CH, 0x81010020U);
    WR1_PROG(REG_0000H, 0x00490005U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_0094H, 0x00000800U);
    WR1_PROG(REG_009CH, 0x80880000U);
    WR1_PROG(REG_0000H, 0x03400021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_0094H, 0x000008e7U);

    WR1_PROG(REG_0094H, 0x0000b480U);
    WR1_PROG(REG_0094H, 0xffffffffU);

    WR1_PROG(REG_0094H, 0x0000b4c0U);
    WR1_PROG(REG_0094H, 0x00000001U);

    WR1_PROG(REG_00D0H, 0x0e340406U);

    for (iLoop = 0U; iLoop < 32U; iLoop++)
    {
        WR1_PROG(REG_009CH, 0x80010000U);
        WR1_PROG(REG_0000H, 0x03440005U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_009CH, 0x81010000U);
        WR1_PROG(REG_0000H, 0x00490005U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0094H, 0x00003420U);

        for (jLoop = 0U; jLoop < 8U; jLoop++)
        {
            WR1_PROG(REG_0094H, 0x00003441U);

            WR1_PROG(REG_0094H, 0x00008c40U);
            WR1_PROG(REG_0094H, 0x0000000fU);

            WR1_PROG(REG_0094H, 0x00016c42U);

            WR1_PROG(REG_0094H, 0x01003862U);

            WR1_PROG(REG_0094H, 0x00002c60U);

            WR1_PROG(REG_0094H, 0x01003c62U);

            WR1_PROG(REG_0094H, 0x00046821U);
        }

        WR1_PROG(REG_0094H, 0x00003420U);

        WR1_PROG(REG_0094H, 0x00003441U);

        WR1_PROG(REG_0094H, 0x00008c40U);
        WR1_PROG(REG_0094H, 0x80000000U);

        WR1_PROG(REG_0094H, 0x38000882U);
        WR1_PROG(REG_0094H, 0x00030020U);

        WR1_PROG(REG_0094H, 0x00002ca0U);

        WR1_PROG(REG_0094H, 0x342028c5U);
        WR1_PROG(REG_0094H, 0x100034c5U);

        WR1_PROG(REG_0094H, 0x00000060U);

        WR1_PROG(REG_0094H, 0x0000b4a0U);
        WR1_PROG(REG_0094H, 0x00000001U);

        WR1_PROG(REG_0094H, 0x00000080U);

        for (jLoop = 0U; jLoop < 31; jLoop++)
        {
            WR1_PROG(REG_0094H, 0x00016c21U);

            WR1_PROG(REG_0094H, 0x00003481U);

            WR1_PROG(REG_0094H, 0x00008c80U);
            WR1_PROG(REG_0094H, 0x80000000U);

            WR1_PROG(REG_0094H, 0x38000882U);
            WR1_PROG(REG_0094H, 0x00030020U);

            WR1_PROG(REG_0094H, 0x00002ca0U);

            WR1_PROG(REG_0094H, 0x342028c5U);
            WR1_PROG(REG_0094H, 0x100034c5U);

            WR1_PROG(REG_0094H, 0x00000060U);

            WR1_PROG(REG_0094H, 0x00003444U);

            WR1_PROG(REG_0094H, 0x0000b4a0U);
            WR1_PROG(REG_0094H, 0x00000001U);

            WR1_PROG(REG_0094H, 0x00000080U);
        }

        WR1_PROG(REG_0094H, 0x00003420U);

        for (jLoop = 0U; jLoop < 32U; jLoop++)
        {
            WR1_PROG(REG_0094H, 0x38008c20U);
            WR1_PROG(REG_0094H, 0x00000001U);
            WR1_PROG(REG_0094H, 0x00020020U);

            WR1_PROG(REG_0094H, 0x00002ce0U);

            WR1_PROG(REG_0094H, 0x00000060U);

            WR1_PROG(REG_0094H, 0x0000a4e0U);
            WR1_PROG(REG_0094H, 0x00010000U);

            WR1_PROG(REG_0094H, 0x00000080U);

            WR1_PROG(REG_0094H, 0x00016821U);
        }
    }

    WR1_PROG(REG_0040H, 0x00001200U);
    WAIT_STS(REG_00C8H, 6, 0);
    WR1_PROG(REG_00D0H, 0x00000000U);
    WR1_PROG(REG_0040H, 0x00000400U);

    WR1_PROG(REG_0094H, 0x00000800U);

    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x00000033U);

    WR1_PROG(REG_0094H, 0x342028c1U);
    WR1_PROG(REG_0094H, 0x2000d011U);

    WR1_PROG(REG_0094H, 0x0000b4a0U);
    WR1_PROG(REG_0094H, 0x00000348U);

    WR1_PROG(REG_0094H, 0x0000b4c0U);
    WR1_PROG(REG_0094H, 0x000000b7U);

    WR1_PROG(REG_0094H, 0x00003467U);
    WR1_PROG(REG_0094H, 0x00008c60U);
    WR1_PROG(REG_0094H, 0x0000ffffU);

    WR1_PROG(REG_0094H, 0x34202865U);
    WR1_PROG(REG_0094H, 0x2000d012U);

    WR1_PROG(REG_0094H, 0x342028c3U);
    WR1_PROG(REG_0094H, 0x2000d012U);

    WR1_PROG(REG_0094H, 0x001068e7U);

    WR1_PROG(REG_0094H, 0x342028e5U);
    WR1_PROG(REG_0094H, 0x2000d013U);

    WR1_PROG(REG_0094H, 0x342028c7U);
    WR1_PROG(REG_0094H, 0x2000d013U);

    WR1_PROG(REG_0094H, 0x00002467U);

    HW_SCE_p_func100(0xa83d5d8cU, 0x7eadca8fU, 0x6d09c745U, 0x11759b8aU);
    WR1_PROG(REG_0094H, 0x38008860U);
    WR1_PROG(REG_0094H, 0x00000400U);
    WR1_PROG(REG_009CH, 0x00000080U);
    WR1_PROG(REG_0040H, 0x00260000U);

    WR1_PROG(REG_0040H, 0x00402000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    WR1_PROG(REG_0008H, 0x00020000U);

    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x0000005AU);

    WR1_PROG(REG_0094H, 0x00000842U);

    WR1_PROG(REG_0094H, 0x00000863U);

    WR1_PROG(REG_0094H, 0x00000884U);

    WR1_PROG(REG_0094H, 0x0000b4a0U);
    WR1_PROG(REG_0094H, 0x00000002U);

    for (iLoop = 0U; iLoop < 16U; iLoop++)
    {
        WR1_PROG(REG_0094H, 0x010038c4U);

        WR1_PROG(REG_0094H, 0x34202826U);
        WR1_PROG(REG_0094H, 0x10005002U);

        WR1_PROG(REG_0094H, 0x00002466U);

        WR1_PROG(REG_0094H, 0x00002c40U);

        WR1_PROG(REG_0094H, 0x00002485U);
    }

    HW_SCE_p_func100(0xbb18c92dU, 0xd1b7947eU, 0xc2b00d79U, 0x610b8d79U);
    WR1_PROG(REG_0094H, 0x38008860U);
    WR1_PROG(REG_0094H, 0x00000100U);
    WR1_PROG(REG_009CH, 0x00000080U);
    WR1_PROG(REG_0040H, 0x00260000U);

    WR1_PROG(REG_0040H, 0x00402000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    WR1_PROG(REG_0008H, 0x00020000U);

    WR1_PROG(REG_0014H, 0x000000a1U);
    WR1_PROG(REG_00D0H, 0x0c000104U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000000U));
    WR1_PROG(REG_009CH, 0x80010020U);
    WR1_PROG(REG_0000H, 0x03410005U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);
    WR1_PROG(REG_0000H, 0x0001000dU);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_0094H, 0x00002c20U);

    WR1_PROG(REG_0094H, 0x38000c00U);
    WR1_PROG(REG_009CH, 0x00000080U);
    WR1_PROG(REG_0040H, 0x00A60000U);

    HW_SCE_p_func100(0x853aaadfU, 0x54ce5f96U, 0x1957d082U, 0xcb612b95U);
    WR1_PROG(REG_0040H, 0x00400000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (CHCK_STS(REG_0040H, 22, 1))
    {
        HW_SCE_p_func102(0x4d21697aU, 0x63972922U, 0x112704b3U, 0x8d17653cU);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_ERR_CRYPTO_SCE_RETRY;
    }
    else
    {
        HW_SCE_p_func100(0x7d294a8aU, 0xd7e82c74U, 0x32f1ca37U, 0xcad81ee6U);

        WR1_PROG(REG_0014H, 0x000000a1U);
        WR1_PROG(REG_00D0H, 0x0c300104U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));
        WR1_PROG(REG_009CH, 0x80040000U);
        WR1_PROG(REG_0000H, 0x03410011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00D4H, 0x00000600U);
        WR1_PROG(REG_00D0H, 0x0e349407U);
        WAIT_STS(REG_00E8H, 0, 0);
        WR1_PROG(REG_00E4H, 0x00200003U);
        WR1_PROG(REG_0000H, 0x00440071U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);
        WR1_PROG(REG_00D0H, 0x0e340505U);
        WR1_PROG(REG_0000H, 0x00440011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WAIT_STS(REG_00E8H, 3, 0);
        WR1_PROG(REG_00E0H, 0x00000000U);
        WR1_PROG(REG_009CH, 0x80040080U);
        WR1_PROG(REG_0000H, 0x03410011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0014H, 0x000000a1U);
        WR1_PROG(REG_00D0H, 0x080000b4U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        HW_SCE_p_func100(0x70b901c3U, 0xe988f40eU, 0x52a1d0deU, 0xd7d32665U);
        WR1_PROG(REG_0014H, 0x000003a1U);
        WR1_PROG(REG_00D0H, 0x08000075U);
        WAIT_STS(REG_0014H, 31, 1);
        WR4_PROG(REG_002CH, change_endian_long(0x00000000U), change_endian_long(0x00000000U),
                 change_endian_long(0x00000000U), change_endian_long(0x00000001U));

        WR1_PROG(REG_00D4H, 0x00000100U);
        WR1_PROG(REG_00D0H, 0x07338d07U);
        WR1_PROG(REG_009CH, 0x81080000U);
        WR1_PROG(REG_0000H, 0x00490021U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00D0H, 0x080000b5U);
        WR1_PROG(REG_0000H, 0x00410011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        HW_SCE_p_func100(0x7597844cU, 0x9cd23c9cU, 0x09496d32U, 0x41ec0357U);
        WR1_PROG(REG_00D0H, 0x08000075U);
        WR1_PROG(REG_0000H, 0x00410011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        HW_SCE_p_func103();
        HW_SCE_p_func100(0x29e252e7U, 0xb25f7a66U, 0xb0d3c5f6U, 0xd1711864U);
        WR1_PROG(REG_0014H, 0x000000a1U);
        WR1_PROG(REG_00D0H, 0x0c2000d4U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        HW_SCE_p_func100(0x681fb388U, 0x6f0ee938U, 0x90378e1aU, 0x11271e99U);
        HW_SCE_p_func103();
        WR1_PROG(REG_0014H, 0x000000a1U);
        WR1_PROG(REG_00D0H, 0x0c200104U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00A0H, 0x00030000U);
        WR1_PROG(REG_0004H, 0x20000000U);
        WR1_PROG(REG_00B0H, 0x00000401U);

        WR1_PROG(REG_0000H, 0x00c10009U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);
        WR1_PROG(REG_0000H, 0x00010009U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0004H, 0x00000000U);
        WR1_PROG(REG_00A0H, 0x00030000U);
        WR1_PROG(REG_00B0H, 0x000074c0U);
        WR1_PROG(REG_0000H, 0x00c00601U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0070H, 0x00008002U);
        WR1_PROG(REG_0078H, 0x00000d01U);

        WR1_PROG(REG_0070H, 0x00008001U);

        WR1_PROG(REG_0078H, 0x00000214U);

        HW_SCE_p_func102(0xd1c60a87U, 0x76f3114eU, 0x34175b96U, 0xe8816ac3U);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_SUCCESS;
    }

    /* FIT body has no default return; keep a fail path for -Wreturn-type. */
    return FSP_ERR_CRYPTO_SCE_FAIL;
}


/* From hw_sce_p_p72.c */
static fsp_err_t HW_SCE_ShaGenerateMessageDigestSub(const uint32_t InData_InitVal[],
                                                    const uint32_t InData_PaddedMsg[],
                                                    uint32_t OutData_MsgDigest[],
                                                    const uint32_t MAX_CNT)
{
    uint32_t iLoop = 0U;

    if (RD1_MASK(REG_0068H, 0x00000016U) != 0) {
        return FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT;
    }

    WR1_PROG(REG_0070H, 0x00720001U);
    WR1_PROG(REG_004CH, 0x00000000U);

    WR1_PROG(REG_00F4H, 0x00000010U);
    WAIT_STS(REG_00F8H, 0, 1);

    WR1_PROG(REG_0014H, 0x000007c4U);
    WAIT_STS(REG_0014H, 31, 1);
    WR8_ADDR(REG_002CH, &InData_InitVal[0]);

    WR1_PROG(REG_00F4H, 0x00000011U);
    WAIT_STS(REG_00F8H, 0, 1);

    WR1_PROG(REG_0014H, 0x00000064U);
    for (iLoop = 0U; iLoop < MAX_CNT; iLoop = iLoop + 16U) {
        WAIT_STS(REG_0014H, 31, 1);
        WR16_ADDR(REG_002CH, &InData_PaddedMsg[iLoop]);
    }

    WAIT_STS(REG_00F8H, 2, 0);

    WR1_PROG(REG_0014H, 0x00000000U);
    WR1_PROG(REG_00F4H, 0x00000100U);
    WR1_PROG(REG_00F4H, 0x00000020U);
    WAIT_STS(REG_00F8H, 1, 1);

    HW_SCE_p_func100(0x7af98838U, 0xf1e9f5feU, 0xb5668247U, 0x756c6419U);
    WR1_PROG(REG_0008H, 0x00004022U);
    WAIT_STS(REG_0008H, 30, 1);
    RD8_ADDR(REG_002CH, &OutData_MsgDigest[0]);

    HW_SCE_p_func102(0x6ca18432U, 0x10c727f4U, 0xefb2823fU, 0x51fcd4a2U);
    WR1_PROG(REG_0068H, 0x00000040U);
    WAIT_STS(REG_0020H, 12, 0);

    return FSP_SUCCESS;
}

/* From hw_sce_p_p40.c / func048 */
#define RSIP_DUMMY_LC  (0x00000002u)

static void HW_SCE_p_func048(const uint32_t ARG1[])
{
    WR1_PROG(REG_0014H, 0x000000c7U);
    WR1_PROG(REG_009CH, 0x80010000U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(ARG1[0]));
    WR1_PROG(REG_0024H, 0x00000000U);
}

static fsp_err_t HW_SCE_LoadHukSub (const uint32_t InData_LC[])
{
    if (RD1_MASK(REG_006CH, 0x00000017U) != 0)
    {
        return FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT;
    }

    WR1_PROG(REG_0070H, 0x00400001U);
    WR1_PROG(REG_004CH, 0x00000000U);

    HW_SCE_p_func048(InData_LC);

    WR1_PROG(REG_0094H, 0x3420a800U);
    WR1_PROG(REG_0094H, 0x00000009U);
    WR1_PROG(REG_009CH, 0x00000080U);
    WR1_PROG(REG_0040H, 0x00A60000U);

    HW_SCE_p_func100(0x56b2f686U, 0x65c531d8U, 0x6316e9a3U, 0x7e311a45U);
    WR1_PROG(REG_0040H, 0x00400000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (CHCK_STS(REG_0040H, 22, 1))
    {
        HW_SCE_p_func102(0x8d7e8408U, 0xccf9de38U, 0x26c28a80U, 0x9f372384U);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_ERR_CRYPTO_SCE_FAIL;
    }
    else
    {
        WR1_PROG(REG_0014H, 0x000003a1U);
        WR1_PROG(REG_00D0H, 0x0a0700f5U);
        WAIT_STS(REG_0014H, 31, 1);
        WR4_PROG(REG_002CH, change_endian_long(0x1812f4dcU), change_endian_long(0x82d61a46U),
                 change_endian_long(0xe6752383U), change_endian_long(0xab0bdbb3U));

        HW_SCE_p_func100(0xa8b2e233U, 0x3410e7d6U, 0xf1a36ec3U, 0x5c889990U);
        WR1_PROG(REG_00D0H, 0x4a470044U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00D0H, 0x0e470484U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x01a5da45U));

        HW_SCE_p_func100(0xb08ec877U, 0x747a76b7U, 0x59c2b07bU, 0xe7b91a0aU);
        WR1_PROG(REG_00D0H, 0x4a470044U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00D0H, 0x0e470494U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x02a5da45U));

        WR1_PROG(REG_0014H, 0x000003a1U);
        WR1_PROG(REG_00D0H, 0x0a0700f5U);
        WAIT_STS(REG_0014H, 31, 1);
        WR4_PROG(REG_002CH, change_endian_long(0xb068951eU), change_endian_long(0xc59ca899U),
                 change_endian_long(0xbb7f581cU), change_endian_long(0xc1127d55U));

        HW_SCE_p_func100(0x3951cfb2U, 0x9cc90b10U, 0x48dc3d50U, 0x310fde59U);
        WR1_PROG(REG_00D4H, 0x40000100U);
        WR1_PROG(REG_00D0H, 0xf7009d05U);
        WR1_PROG(REG_00D8H, 0x20000000U);
        WR1_PROG(REG_0000H, 0x00480011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00D4H, 0x40000000U);
        WR1_PROG(REG_00D0H, 0xf7008d05U);
        WR1_PROG(REG_00D8H, 0x20000010U);
        WR1_PROG(REG_0000H, 0x00480011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00A0H, 0x00010000U);

        WR1_PROG(REG_00B0H, 0x0000140eU);
        WR1_PROG(REG_0000H, 0x00c10021U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00D4H, 0x40000000U);
        WR1_PROG(REG_00D0H, 0x07008d05U);
        WR1_PROG(REG_00D8H, 0x20000020U);
        WR1_PROG(REG_0000H, 0x00480011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);
        WR1_PROG(REG_00D0H, 0x8c100005U);
        WR1_PROG(REG_0000H, 0x00410011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00B0H, 0x0000180eU);
        WR1_PROG(REG_00D0H, 0x08000085U);
        WR1_PROG(REG_0000H, 0x00430011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        HW_SCE_p_func100(0x7bbaae3fU, 0x09fe85a2U, 0xc06fb7bfU, 0xf43c3524U);
        WR1_PROG(REG_00D0H, 0x08000095U);
        WR1_PROG(REG_0000H, 0x00430011U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00A0H, 0x00010000U);

        WR1_PROG(REG_00B0H, 0x00000492U);
        WR1_PROG(REG_0000H, 0x00c00005U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);
        WR1_PROG(REG_009CH, 0x81010000U);
        WR1_PROG(REG_0000H, 0x00c90005U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0014H, 0x000002a1U);
        WR1_PROG(REG_00D4H, 0x40000000U);
        WR1_PROG(REG_00D0H, 0x4a008044U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00D4H, 0x40000000U);
        WR1_PROG(REG_00D0H, 0x0e008104U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x01d65991U));

        WR1_PROG(REG_00D4H, 0x40000000U);
        WR1_PROG(REG_00D0H, 0x0e008104U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x02d65991U));

        WR1_PROG(REG_00B0H, 0x00001498U);
        WR1_PROG(REG_0000H, 0x00c10021U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        HW_SCE_p_func100(0x60eb9b86U, 0xf4aa33bdU, 0xe03212a0U, 0x73bfadadU);
        WR1_PROG(REG_00D0H, 0x4a470044U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00D0H, 0x0e4704c4U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x01417d25U));

        WR1_PROG(REG_00D0H, 0x4a040044U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000000U));

        WR1_PROG(REG_00D0H, 0x0e040504U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0xc4406986U));

        WR1_PROG(REG_00B0H, 0x00000493U);
        WR1_PROG(REG_0000H, 0x00c10009U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_00B0H, 0x00000494U);
        WR1_PROG(REG_0000H, 0x00c10009U);
        WAIT_STS(REG_0004H, 30, 0);
        WR1_PROG(REG_0040H, 0x00001800U);

        WR1_PROG(REG_0078H, 0x00000202U);

        HW_SCE_p_func102(0x21a657feU, 0xabcf9e62U, 0xca25fda0U, 0x04ff1dbfU);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_SUCCESS;
    }
}

/* Order follows FIT McuSpecificInit: MSTP, reset, SelfCheck, LE, HUK.
 * Extra delays, a second SoftwareReset, and SelfCheck2 retries were only
 * workarounds during early hung-HUK debugging. They are not part of the stock
 * init path and are omitted here.
 */
int rsip_hw_init(void)
{
    fsp_err_t iret;

    RSIP_MSTP_CLEAR();

    HW_SCE_SoftwareResetSub();

    iret = HW_SCE_SelfCheck1Sub();
    if (iret != FSP_SUCCESS) {
        return (int)iret;
    }

    /* LE mode is part of FIT McuSpecificInit; CM tables in this file assume LE. */
    WR1_PROG(REG_0018H, R_RSIP_LITTLE_ENDIAN_MODE);
    WR1_PROG(REG_001CH, R_RSIP_LITTLE_ENDIAN_MODE);

    iret = HW_SCE_SelfCheck2Sub();
    if (iret != FSP_SUCCESS) {
        return RSIP_ERR_SELFCHECK2;
    }

    /* RSIP_DUMMY_LC 0x2 is the lifecycle value FIT uses on the RSKRX261 path. */
    {
        uint32_t lc_state = RSIP_DUMMY_LC;
        iret = HW_SCE_LoadHukSub(&lc_state);
        if (iret != FSP_SUCCESS) {
            return RSIP_ERR_HUK;
        }
    }

    return 0;
}

/*
 * IV words are byte-swapped vs FIPS constants, same as mbedtls_sha256_alt for RSIP.
 * HW then LE-stores the state so the 32-byte digest matches the usual FIPS image
 * on little-endian RX (checked by rsip_sha256_selftest).
 *
 * Sharing is built from the oneshot path upward:
 *   - sha256_compress_blocks: full 64-byte blocks into state[8]
 *   - sha256_final_pad: PKCS-style pad + bit-length + final digest
 * compute uses only those plus a local state[8] (no ctx). init/update/finish
 * add the streaming buffer on top.
 *
 * IV is copied with memcpy from s_sha256_iv so one .rodata image is shared
 * by compute and init (smaller total than per-call mov.l immediates when both
 * paths may remain, and avoids duplicating eight immediates in .text).
 *
 * Build with -ffunction-sections and -Wl,--gc-sections so an app that only
 * references compute can drop the public multipart symbols, and the reverse.
 */

static const uint32_t s_sha256_iv[8] = {
    0x67E6096Au, 0x85AE67BBu, 0x72F36E3Cu, 0x3AF54FA5u,
    0x7F520E51u, 0x8C68059Bu, 0xABD9831Fu, 0x19CDE05Bu
};

#if defined(__GNUC__)
#define RSIP_SHA_INLINE static inline __attribute__((always_inline))
#else
#define RSIP_SHA_INLINE static inline
#endif

/* Compress complete 64-byte blocks. state is a plain 8-word array (not a ctx). */
RSIP_SHA_INLINE int sha256_compress_blocks(uint32_t state[8],
                                           const uint8_t *data, size_t nblocks)
{
    if (nblocks == 0u) {
        return 0;
    }

    if (((uintptr_t)data & 3u) == 0u) {
        const uint32_t *wp = (const uint32_t *)(const void *)data;
        while (nblocks > 0u) {
            fsp_err_t err = HW_SCE_ShaGenerateMessageDigestSub(
                state, wp, state, 16u);
            if (err != FSP_SUCCESS) {
                return (int)err;
            }
            wp += 16u;
            nblocks--;
        }
    } else {
        while (nblocks > 0u) {
            uint32_t words[16];
            fsp_err_t err;
            memcpy(words, data, 64u);
            err = HW_SCE_ShaGenerateMessageDigestSub(
                state, words, state, 16u);
            if (err != FSP_SUCCESS) {
                return (int)err;
            }
            data += 64u;
            nblocks--;
        }
    }
    return 0;
}

/*
 * Final pad of a 0..63 byte tail and emit digest.
 * total_lo/total_hi are the full message length in bytes (not bits).
 */
RSIP_SHA_INLINE int sha256_final_pad(uint32_t state[8],
                                     const uint8_t *tail, size_t tail_len,
                                     uint32_t total_lo, uint32_t total_hi,
                                     uint8_t digest[32])
{
    uint32_t words[16];
    uint8_t *pad = (uint8_t *)(void *)words;
    uint32_t n = (uint32_t)tail_len;

    if (n != 0u) {
        memcpy(pad, tail, n);
    }
    pad[n++] = 0x80u;
    if (n > 56u) {
        if (n < 64u) {
            memset(pad + n, 0, 64u - n);
        }
        fsp_err_t err = HW_SCE_ShaGenerateMessageDigestSub(
            state, words, state, 16u);
        if (err != FSP_SUCCESS) {
            return (int)err;
        }
        n = 0u;
    }
    if (n < 56u) {
        memset(pad + n, 0, 56u - n);
    }

    uint32_t bit_lo = total_lo << 3;
    uint32_t bit_hi = (total_hi << 3) | (total_lo >> 29);

    pad[56] = (uint8_t)(bit_hi >> 24);
    pad[57] = (uint8_t)(bit_hi >> 16);
    pad[58] = (uint8_t)(bit_hi >>  8);
    pad[59] = (uint8_t)(bit_hi);
    pad[60] = (uint8_t)(bit_lo >> 24);
    pad[61] = (uint8_t)(bit_lo >> 16);
    pad[62] = (uint8_t)(bit_lo >>  8);
    pad[63] = (uint8_t)(bit_lo);

    return (int)HW_SCE_ShaGenerateMessageDigestSub(
        state, words, (uint32_t *)(void *)digest, 16u);
}

int rsip_sha256_compute(const uint8_t *msg, size_t len,
                        uint8_t digest[RSIP_SHA256_DIGEST_SIZE])
{
    /* msg must be non-NULL even for len==0 (avoids null+0 when forming tail).
     * total_hi is fixed at 0: one-shot length fits in 32 bits on this MCU class. */
    if (msg == NULL || digest == NULL) {
        return -1;
    }

    uint32_t state[8];
    memcpy(state, s_sha256_iv, sizeof(s_sha256_iv));

    size_t nblocks = len >> 6;
    int rc = sha256_compress_blocks(state, msg, nblocks);
    if (rc != 0) {
        return rc;
    }

    size_t rem = len & 63u;
    return sha256_final_pad(state, msg + (nblocks << 6), rem,
                            (uint32_t)len, 0u, digest);
}

int rsip_sha256_init(struct rsip_sha256_ctx *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    memcpy(ctx->state, s_sha256_iv, sizeof(s_sha256_iv));
    ctx->total_lo   = 0u;
    ctx->total_hi   = 0u;
    ctx->buffer_len = 0u;
    return 0;
}

int rsip_sha256_update(struct rsip_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len > 0u)) {
        return -1;
    }

    uint32_t new_lo = ctx->total_lo + (uint32_t)len;
    if (new_lo < ctx->total_lo) {
        ctx->total_hi++;
    }
    ctx->total_lo = new_lo;

    if (ctx->buffer_len > 0u) {
        uint32_t need = 64u - ctx->buffer_len;
        if ((uint32_t)len < need) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += (uint32_t)len;
            return 0;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, need);
        int rc = sha256_compress_blocks(ctx->state, ctx->buffer, 1u);
        if (rc != 0) {
            return rc;
        }
        data += need;
        len  -= need;
        ctx->buffer_len = 0u;
    }

    if (len >= 64u) {
        size_t nblocks = len >> 6;
        int rc = sha256_compress_blocks(ctx->state, data, nblocks);
        if (rc != 0) {
            return rc;
        }
        data += nblocks << 6;
        len  &= 63u;
    }

    if (len > 0u) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = (uint32_t)len;
    }
    return 0;
}

int rsip_sha256_finish(struct rsip_sha256_ctx *ctx, uint8_t digest[RSIP_SHA256_DIGEST_SIZE])
{
    if (ctx == NULL || digest == NULL) {
        return -1;
    }
    return sha256_final_pad(ctx->state,
                            ctx->buffer, ctx->buffer_len,
                            ctx->total_lo, ctx->total_hi,
                            digest);
}

int rsip_sha256_selftest(void)
{
    /* Empty-message digest (FIPS 180-4). */
    static const uint8_t expected[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    uint8_t dig[32];
    int r = rsip_sha256_compute((const uint8_t *)"", 0, dig);
    if (r != 0) {
        return -2;
    }
    return memcmp(dig, expected, 32) == 0 ? 0 : -1;
}

/* ECDSA path: pf1 + func070/071/073 + DomainParam_NIST_P256 */
static void HW_SCE_p_func070(const uint32_t ARG1[]);
static void HW_SCE_p_func071(const uint32_t ARG1[]);
static void HW_SCE_p_func073(const uint32_t ARG1[]);
static void HW_SCE_p_func073_sub001(uint32_t arg1, uint32_t arg2, uint32_t arg3);
static void HW_SCE_p_func073_sub002(uint32_t arg1);
static void HW_SCE_p_func073_sub003(uint32_t arg1, uint32_t arg2);

/* DomainParams.c __LIT branch; pairs with LE mode and BE byte buffers cast to words. */
static const uint32_t DomainParam_NIST_P256[72] = {
    0xb32549c4u,0x940b39a4u,0x577bd5c9u,0xfd7bf7b6u,
    0xba887d30u,0xf5f64f20u,0x1328d683u,0xe410c83bu,
    0x8c12010cu,0x7ba10989u,0xaebfdf02u,0xdf781bfcu,
    0xd024199fu,0x33762c72u,0xbca9b2e9u,0x0f238b70u,
    0x745e51f9u,0xa18d048au,0x2bf412eau,0x27370971u,
    0xb91cc7e0u,0x5350cf26u,0x5327c769u,0x06ecf6c3u,
    0x51df4211u,0x98c82478u,0x39990d3cu,0xf7b33fa0u,
    0x7fbd53b4u,0x8b389095u,0x489e240au,0x69c921c0u,
    0x1e0685b3u,0x7498da0au,0x269032c3u,0xa6dcf40eu,
    0xfe14f043u,0xd10e2198u,0x1b2b41bau,0x042ebae7u,
    0xce17a1beu,0x35daa8f9u,0x0ab25e78u,0xbf65e657u,
    0x1ce8d455u,0x5a55d548u,0x2dcbb45au,0xa6f5e3d4u,
    0x4e16097bu,0xafe09388u,0xaadc5c8fu,0x95cc0fb8u,
    0xa757033eu,0x7bfab7d2u,0x05a62824u,0xf675eb6fu,
    0x3cb139a6u,0xeaa01d18u,0x49b1dc9bu,0x7cfa76b6u,
    0x8fcd006du,0x34e69ae7u,0xfb73d046u,0x63b7b183u,
    0x7884ab0du,0xf35678e1u,0xb5233189u,0xb1727f8cu,
    0x02ff452eu,0x9eb2217du,0xfc306c7eu,0x189fcf44u
};


static void HW_SCE_p_func071 (const uint32_t ARG1[])
{
    WR1_PROG(REG_0094H, 0x30003000U);
    WR1_PROG(REG_0094H, 0x00050020U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01942287U);
    WR1_PROG(REG_0094H, 0x00030040U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01881fe1U);
    WR1_PROG(REG_0094H, 0x00070040U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01b03468U);
    WR1_PROG(REG_0094H, 0x00000080U);

    WR1_PROG(REG_00D0H, 0x300710c4U);
    WR1_PROG(REG_009CH, 0x81010020U);
    WR1_PROG(REG_0000H, 0x00490005U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00A0H, 0x20010000U);
    WR1_PROG(REG_00B0H, 0x00001419U);
    WR1_PROG(REG_0014H, 0x00000fc1U);
    WR1_PROG(REG_00D4H, 0x00000300U);
    WR1_PROG(REG_00D0H, 0xf7049d07U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[0]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[4]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x0000141eU);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[8]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[12]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00D0H, 0x07040d05U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[16]);

    WR1_PROG(REG_00D0H, 0x8c100005U);
    WR1_PROG(REG_0000H, 0x00410011U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);
}

static void HW_SCE_p_func073_sub001(uint32_t arg1, uint32_t arg2, uint32_t arg3)
{
   WR1_PROG(REG_00B4H, arg1);
   WR1_PROG(REG_00B8H, arg2);

   WR1_PROG(REG_00A4H, arg3);
   WR1_PROG(REG_00A0H, 0x20010001U);
   WAIT_STS(REG_00A8H, 0, 1);
   WR1_PROG(REG_00ACH, 0x00000001U);
}

static void HW_SCE_p_func073_sub002(uint32_t arg1)
{
   WR1_PROG(REG_00B0H, arg1);
   WR1_PROG(REG_009CH, 0x80820005U);
   WR1_PROG(REG_0000H, 0x03430009U);
   WAIT_STS(REG_0004H, 30, 0);
   WR1_PROG(REG_0040H, 0x00001800U);
}

static void HW_SCE_p_func073_sub003(uint32_t arg1, uint32_t arg2)
{
	WR1_PROG(REG_00B0H, arg1);
	WR1_PROG(REG_0000H, arg2);
	WAIT_STS(REG_0004H, 30, 0);
	WR1_PROG(REG_0040H, 0x00001800U);
}


static void HW_SCE_p_func070 (const uint32_t ARG1[])
{
    WR1_PROG(REG_0094H, 0x30003000U);
    WR1_PROG(REG_0094H, 0x00050020U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01728832U);
    WR1_PROG(REG_0094H, 0x00030040U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01e611afU);
    WR1_PROG(REG_0094H, 0x00070040U);
    WR1_PROG(REG_0094H, 0x0000b420U);
    WR1_PROG(REG_0094H, 0x01d65d11U);
    WR1_PROG(REG_0094H, 0x00000080U);

    WR1_PROG(REG_00D0H, 0x300710c4U);
    WR1_PROG(REG_009CH, 0x81010020U);
    WR1_PROG(REG_0000H, 0x00490005U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00A0H, 0x20010000U);
    WR1_PROG(REG_00B0H, 0x00001405U);
    WR1_PROG(REG_0014H, 0x00002fc1U);
    WR1_PROG(REG_00D4H, 0x00000b00U);
    WR1_PROG(REG_00D0H, 0xf7049d07U);

    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[20]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[24]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x00001437U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[28]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[32]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x0000145fU);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[36]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[40]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x00001464U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[44]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[48]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x0000140aU);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[52]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[56]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00B0H, 0x0000145aU);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[60]);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[64]);
    WR1_PROG(REG_0000H, 0x00c10021U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);

    WR1_PROG(REG_00D0H, 0x07040d05U);
    WAIT_STS(REG_0014H, 31, 1);
    WR4_ADDR(REG_002CH, &ARG1[68]);

    WR1_PROG(REG_00D0H, 0x8c100005U);
    WR1_PROG(REG_0000H, 0x00410011U);
    WAIT_STS(REG_0004H, 30, 0);
    WR1_PROG(REG_0040H, 0x00001800U);
}

static void HW_SCE_p_func073 (const uint32_t ARG1[])
{
    uint32_t iLoop = 0U;
    uint32_t jLoop = 0U;
    uint32_t kLoop = 0U;

    HW_SCE_p_func070(ARG1);

    WR1_PROG(REG_00A0H, 0x20010000U);

    WR1_PROG(REG_00B8H, 0x0000000aU);

    WR1_PROG(REG_00A4H, 0x04040010U);

    WR1_PROG(REG_00A0H, 0x20010001U);
    WAIT_STS(REG_00A8H, 0, 1);
    WR1_PROG(REG_00ACH, 0x00000001U);

    HW_SCE_p_func073_sub003(0x0000141eU, 0x00c0001dU);
    WR1_PROG(REG_0014H, 0x000000a5U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x00000001U));

    HW_SCE_p_func073_sub001(0x001e000aU, 0x00140000U, 0x0404000aU);
    HW_SCE_p_func073_sub001(0x00690014U, 0x00190000U, 0x0404000aU);

    WR1_PROG(REG_0040H, 0x00210000U);

    HW_SCE_p_func073_sub001(0x001e0069U, 0x00190000U, 0x0404000aU);

    WR1_PROG(REG_0040H, 0x00210000U);

    HW_SCE_p_func073_sub001(0x006e0014U, 0x00190000U, 0x0404000aU);

    WR1_PROG(REG_0040H, 0x00210000U);

    HW_SCE_p_func073_sub001(0x001e006eU, 0x00190000U, 0x0404000aU);

    WR1_PROG(REG_0040H, 0x00210000U);

    HW_SCE_p_func100(0x96707843U, 0xf0e8a3b4U, 0x99acd4a9U, 0x7c332f65U);
    WR1_PROG(REG_0040H, 0x00400000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (CHCK_STS(REG_0040H, 22, 1))
    {
        WR1_PROG(REG_0094H, 0x00000800U);

        HW_SCE_p_func101(0x461edcd2U, 0xf49dffe3U, 0xc7ee28deU, 0x6b2e0349U);
    }
    else
    {
        HW_SCE_p_func100(0x7b19f51cU, 0x11d3d6f6U, 0xfcd9bae7U, 0xd70e7b9eU);

        HW_SCE_p_func073_sub001(0x001e0014U, 0x00190000U, 0x0404000aU);

        WR1_PROG(REG_00B4H, 0x0019006eU);
        WR1_PROG(REG_00B8H, 0x000f000aU);

        WR1_PROG(REG_00A4H, 0x04040000U);
        WR1_PROG(REG_0008H, 0x00020000U);
        WR1_PROG(REG_00A0H, 0x20010001U);
        WAIT_STS(REG_00A8H, 0, 1);
        WR1_PROG(REG_00ACH, 0x00000001U);
        WR1_PROG(REG_0040H, 0x00000d00U);

        HW_SCE_p_func073_sub001(0x005a000fU, 0x0014000aU, 0x04040002U);

        HW_SCE_p_func073_sub003(0x00001423U, 0x00c00021U);

        HW_SCE_p_func073_sub001(0x00230072U, 0x000f0000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x0014000fU, 0x000f000aU, 0x04040002U);

        HW_SCE_p_func073_sub001(0x00140069U, 0x0032000aU, 0x04040002U);

        WR1_PROG(REG_00B8H, 0x00000005U);

        WR1_PROG(REG_00A4H, 0x04040010U);

        WR1_PROG(REG_00A0H, 0x20010001U);
        WAIT_STS(REG_00A8H, 0, 1);
        WR1_PROG(REG_00ACH, 0x00000001U);

        HW_SCE_p_func073_sub001(0x00230069U, 0x000a0000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x00370076U, 0x004b0005U, 0x04040002U);

        HW_SCE_p_func073_sub001(0x0037007aU, 0x00500005U, 0x04040002U);

        HW_SCE_p_func073_sub003(0x00001414U, 0x00c0001dU);

        WR1_PROG(REG_0014H, 0x000000a5U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000001U));

        HW_SCE_p_func073_sub001(0x00140037U, 0x00550005U, 0x04040002U);

        HW_SCE_p_func073_sub001(0x0023005fU, 0x00280000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x00230005U, 0x002d0000U, 0x04040009U);

        HW_SCE_p_func073_sub003(0x00000415U, 0x00c00009U);

        HW_SCE_p_func073_sub003(0x0000041aU, 0x00c00009U);

        HW_SCE_p_func071(ARG1);

        HW_SCE_p_func073_sub001(0x00230019U, 0x005a0000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x0023001eU, 0x005f0000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x00230055U, 0x00640000U, 0x04040009U);

        HW_SCE_p_func073_sub003(0x0000046fU, 0x00c00009U);

        HW_SCE_p_func073_sub001(0x004b005aU, 0x00140000U, 0x0404000aU);

        WR1_PROG(REG_0040H, 0x00210000U);

        HW_SCE_p_func073_sub001(0x005a004bU, 0x00140000U, 0x0404000aU);

        WR1_PROG(REG_0040H, 0x00210000U);

        HW_SCE_p_func073_sub001(0x0050005fU, 0x00140000U, 0x0404000aU);

        WR1_PROG(REG_0040H, 0x00210000U);

        HW_SCE_p_func073_sub001(0x005f0050U, 0x00140000U, 0x0404000aU);

        WR1_PROG(REG_0040H, 0x00210000U);

        HW_SCE_p_func100(0x81742749U, 0x678b86e7U, 0x224da4abU, 0x71fa78aeU);
        WR1_PROG(REG_0040H, 0x00400000U);
        WR1_PROG(REG_0024H, 0x00000000U);

        if (CHCK_STS(REG_0040H, 22, 1))
        {
            HW_SCE_p_func073_sub001(0x00550064U, 0x00730005U, 0x04040013U);

            WR1_PROG(REG_0040H, 0x00000d00U);

            HW_SCE_p_func101(0x4c2d21d4U, 0xe475db33U, 0x683ff184U, 0xedda1049U);
        }
        else
        {
            HW_SCE_p_func073_sub001(0x00000064U, 0x0073002dU, 0x04040014U);

            WR1_PROG(REG_0040H, 0x00000d00U);

            HW_SCE_p_func101(0xd495c2fcU, 0xa26bbe07U, 0xa4dc38ebU, 0x7372a4c5U);
        }

        HW_SCE_p_func073_sub001(0x0023000fU, 0x00370000U, 0x04040009U);

        HW_SCE_p_func073_sub001(0x00190019U, 0x00190000U, 0x0404000aU);

        HW_SCE_p_func073_sub001(0x001e001eU, 0x001e0000U, 0x0404000aU);

        HW_SCE_p_func073_sub001(0x00230023U, 0x00230000U, 0x0404000aU);

        WR1_PROG(REG_0094H, 0x00000800U);
        for (iLoop = 0U; iLoop < 2U; iLoop++)
        {
            WR1_PROG(REG_0094H, 0x000008a5U);

            WR1_PROG(REG_0094H, 0x38000c00U);
            WR1_PROG(REG_009CH, 0x00000080U);
            WR1_PROG(REG_0040H, 0x00260000U);

            HW_SCE_p_func100(0x97a7743dU, 0x99736c8eU, 0x2a1e19e8U, 0x6142b08fU);
            WR1_PROG(REG_0040H, 0x00400000U);
            WR1_PROG(REG_0024H, 0x00000000U);

            if (CHCK_STS(REG_0040H, 22, 1))
            {
                HW_SCE_p_func073_sub002(0x00000834U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x00000835U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x0000082fU);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x00000830U);

                HW_SCE_p_func101(0x18391f0aU, 0x9434f682U, 0x1d37c544U, 0x2eb285d9U);
            }
            else
            {
                HW_SCE_p_func073_sub002(0x00000836U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x00000837U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x00000831U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000008U);

                HW_SCE_p_func073_sub002(0x00000832U);

                HW_SCE_p_func101(0xa02ea37cU, 0x753b1906U, 0x8b02332bU, 0xf9b994d7U);
            }

            WR1_PROG(REG_0094H, 0x00000821U);

            for (jLoop = 0U; jLoop < 4; jLoop++)
            {
                WR1_PROG(REG_0094H, 0x000034a1U);

                WR1_PROG(REG_0094H, 0x00026ca5U);

                WR1_PROG(REG_0094H, 0x00003865U);

                WR1_PROG(REG_0094H, 0x0000a4a0U);
                WR1_PROG(REG_0094H, 0x00000010U);

                WR1_PROG(REG_0094H, 0x00003885U);

                WR1_PROG(REG_0094H, 0x00000842U);

                for (kLoop = 0U; kLoop < 32U; kLoop++)
                {
                    WR1_PROG(REG_0094H, 0x000008a5U);

                    WR1_PROG(REG_0094H, 0x01816ca3U);
                    WR1_PROG(REG_0094H, 0x01816ca4U);
                    WR1_PROG(REG_0094H, 0x00016c63U);
                    WR1_PROG(REG_0094H, 0x00016c84U);

                    WR1_PROG(REG_0094H, 0x38000ca5U);
                    WR1_PROG(REG_009CH, 0x00000080U);
                    WR1_PROG(REG_0040H, 0x00A60000U);

                    HW_SCE_p_func100(0x587bbb83U, 0x0022ea55U, 0x372910e8U, 0x252d8dd4U);
                    WR1_PROG(REG_0040H, 0x00400000U);
                    WR1_PROG(REG_0024H, 0x00000000U);

                    if (CHCK_STS(REG_0040H, 22, 1))
                    {
                        HW_SCE_p_func100(0x8789c53fU, 0xa4604616U, 0x276b43b3U, 0xe05d8418U);

                        HW_SCE_p_func073_sub003(0x00001414U, 0x00c00021U);

                        WR1_PROG(REG_0094H, 0x00007c05U);
                        WR1_PROG(REG_0040H, 0x00600000U);
                        WR1_PROG(REG_0024H, 0x00000000U);

                        if (RD1_MASK(REG_0044H, 0xffffffffU) == 0x00000001U)
                        {
                            HW_SCE_p_func073_sub001(0x0014004bU, 0x003c0000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140050U, 0x00410000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140055U, 0x00460000U, 0x04040009U);

                            HW_SCE_p_func101(0xf9241590U, 0x0e3ed9faU, 0x7b5102e8U, 0x28220df2U);
                        }
                        else if (RD1_MASK(REG_0044H, 0xffffffffU) == 0x00000002U)
                        {
                            HW_SCE_p_func073_sub001(0x0014005aU, 0x003c0000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x0014005fU, 0x00410000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140064U, 0x00460000U, 0x04040009U);

                            HW_SCE_p_func101(0xde6d47c4U, 0x036ba384U, 0x669ed9a3U, 0xb47ced65U);
                        }
                        else if (RD1_MASK(REG_0044H, 0xffffffffU) == 0x00000003U)
                        {
                            HW_SCE_p_func073_sub001(0x00140069U, 0x003c0000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x0014006eU, 0x00410000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140073U, 0x00460000U, 0x04040009U);

                            HW_SCE_p_func101(0xbafeaaacU, 0xac3a80cdU, 0xf44b0441U, 0x94da01fcU);
                        }

                        HW_SCE_p_func073_sub003(0x00001414U, 0x00c0001dU);

                        WR1_PROG(REG_0014H, 0x000000a5U);
                        WAIT_STS(REG_0014H, 31, 1);
                        WR1_PROG(REG_002CH, change_endian_long(0x00000001U));

                        HW_SCE_p_func073_sub001(0x00140019U, 0x000f0000U, 0x0404000aU);

                        WR1_PROG(REG_0040H, 0x00a10000U);

                        HW_SCE_p_func073_sub001(0x00140023U, 0x000f0000U, 0x0404000aU);

                        WR1_PROG(REG_0040H, 0x00a10000U);

                        HW_SCE_p_func100(0xc8ff75bdU, 0x67f58e57U, 0x9b6b6986U, 0xabfcb44aU);
                        WR1_PROG(REG_0040H, 0x00400000U);
                        WR1_PROG(REG_0024H, 0x00000000U);

                        if (CHCK_STS(REG_0040H, 22, 1))
                        {                           
                            HW_SCE_p_func073_sub001(0x00000023U, 0x0023002dU, 0x04040014U);

                            WR1_PROG(REG_0040H, 0x00000d00U);

                            HW_SCE_p_func073_sub001(0x0014003cU, 0x000f0000U, 0x0404000aU);

                            WR1_PROG(REG_0040H, 0x00a10000U);

                            HW_SCE_p_func073_sub001(0x00140046U, 0x000f0000U, 0x0404000aU);

                            WR1_PROG(REG_0040H, 0x00a10000U);

                            HW_SCE_p_func100(0x4646ea6eU, 0x9000bdcfU, 0x6786791bU, 0x2a7d6b46U);
                            WR1_PROG(REG_0040H, 0x00400000U);
                            WR1_PROG(REG_0024H, 0x00000000U);

                            if (CHCK_STS(REG_0040H, 22, 1))
                            {
                                HW_SCE_p_func073_sub001(0x003c0019U, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func073_sub001(0x0019003cU, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func073_sub001(0x0041001eU, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func073_sub001(0x001e0041U, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func073_sub001(0x00460023U, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func073_sub001(0x00230046U, 0x000f0000U, 0x0404000aU);

                                WR1_PROG(REG_0040H, 0x00210000U);

                                HW_SCE_p_func100(0xc61f3c33U, 0xfcb7c254U, 0xe84b2bacU, 0x333d4236U);
                                WR1_PROG(REG_0040H, 0x00400000U);
                                WR1_PROG(REG_0024H, 0x00000000U);

                                if (CHCK_STS(REG_0040H, 22, 1))
                                {
                                    HW_SCE_p_func073_sub001(0x00460023U, 0x00230005U, 0x04040013U);

                                    WR1_PROG(REG_0040H, 0x00000d00U);

                                    HW_SCE_p_func101(0xa67a402bU, 0xa733523aU, 0xc0d96ed4U, 0x7d9221f7U);
                                }
                                else
                                {
                                    HW_SCE_p_func073_sub001(0x00000023U, 0x0023002dU, 0x04040014U);

                                    WR1_PROG(REG_0040H, 0x00000d00U);

                                    HW_SCE_p_func101(0x20efed06U, 0x4ff03d6eU, 0x0218b88aU, 0x7a499288U);
                                }
                            }
                            else
                            {
                                HW_SCE_p_func101(0xd25d3ca3U, 0x251e100bU, 0x84599bc1U, 0x27b9ccd2U);
                            }
                        }
                        else
                        {
                            HW_SCE_p_func073_sub003(0x00001414U, 0x00c00021U);

                            HW_SCE_p_func073_sub001(0x0014003cU, 0x00190000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140041U, 0x001e0000U, 0x04040009U);

                            HW_SCE_p_func073_sub001(0x00140046U, 0x00230000U, 0x04040009U);

                            HW_SCE_p_func101(0xdb780cc4U, 0x158f1fe3U, 0xe38fcabaU, 0x134eca37U);
                        }
                    }
                    else
                    {
                        HW_SCE_p_func073_sub003(0x00001414U, 0x00c0001dU);
                        WR1_PROG(REG_0014H, 0x000000a5U);
                        WAIT_STS(REG_0014H, 31, 1);
                        WR1_PROG(REG_002CH, change_endian_long(0x00000001U));

                        HW_SCE_p_func073_sub001(0x00140019U, 0x000f0000U, 0x0404000aU);

                        WR1_PROG(REG_0040H, 0x00a10000U);

                        HW_SCE_p_func073_sub001(0x00140023U, 0x000f0000U, 0x0404000aU);

                        WR1_PROG(REG_0040H, 0x00a10000U);

                        HW_SCE_p_func100(0xf3fdcfe2U, 0x0585be02U, 0xdbec79f3U, 0x6f262f50U);
                        WR1_PROG(REG_0040H, 0x00400000U);
                        WR1_PROG(REG_0024H, 0x00000000U);

                        if (CHCK_STS(REG_0040H, 22, 1))
                        {
                            HW_SCE_p_func073_sub001(0x00000023U, 0x0023002dU, 0x04040014U);

                            WR1_PROG(REG_0040H, 0x00000d00U);

                            HW_SCE_p_func101(0xedf20355U, 0x73be5eb5U, 0x89b9faebU, 0x2a9543afU);
                        }
                        else
                        {
                            HW_SCE_p_func101(0x7e63e379U, 0x55aa9fe2U, 0xb25699f5U, 0x5a7cd6e5U);
                        }
                    }

                    WR1_PROG(REG_0094H, 0x00002c40U);
                    HW_SCE_p_func101(0x461b5f5fU, 0x67b0288fU, 0x705fa755U, 0x236afc80U);
                }

                WR1_PROG(REG_0094H, 0x38008840U);
                WR1_PROG(REG_0094H, 0x00000020U);
                WR1_PROG(REG_009CH, 0x00000080U);
                WR1_PROG(REG_0040H, 0x00260000U);

                WR1_PROG(REG_0040H, 0x00402000U);
                WR1_PROG(REG_0024H, 0x00000000U);

                WR1_PROG(REG_0094H, 0x00002c20U);

                HW_SCE_p_func101(0x8b659b51U, 0x90403728U, 0x1befae16U, 0x60de17f0U);
            }

            WR1_PROG(REG_0094H, 0x38008820U);
            WR1_PROG(REG_0094H, 0x00000004U);
            WR1_PROG(REG_009CH, 0x00000080U);
            WR1_PROG(REG_0040H, 0x00260000U);

            WR1_PROG(REG_0040H, 0x00402000U);
            WR1_PROG(REG_0024H, 0x00000000U);

            WR1_PROG(REG_0094H, 0x00002c00U);

            HW_SCE_p_func101(0xa4f008abU, 0x4ebd8a80U, 0x0b27fd1aU, 0x59133c90U);
        }

        WR1_PROG(REG_0094H, 0x38008800U);
        WR1_PROG(REG_0094H, 0x00000002U);
        WR1_PROG(REG_009CH, 0x00000080U);
        WR1_PROG(REG_0040H, 0x00260000U);

        WR1_PROG(REG_0040H, 0x00402000U);
        WR1_PROG(REG_0024H, 0x00000000U);

        HW_SCE_p_func073_sub003(0x00001414U, 0x00c00021U);

        HW_SCE_p_func073_sub001(0x0014000aU, 0x00690000U, 0x04040009U);

        HW_SCE_p_func073_sub003(0x00001414U, 0x00c0001dU);

        WR1_PROG(REG_0014H, 0x000000a5U);
        WAIT_STS(REG_0014H, 31, 1);
        WR1_PROG(REG_002CH, change_endian_long(0x00000001U));

        HW_SCE_p_func073_sub001(0x00140023U, 0x002d0000U, 0x0404000aU);

        WR1_PROG(REG_0040H, 0x00210000U);

        HW_SCE_p_func100(0xec821bfdU, 0x2c637115U, 0x8e8726dbU, 0x26e17208U);
        WR1_PROG(REG_0040H, 0x00400000U);
        WR1_PROG(REG_0024H, 0x00000000U);

        if (CHCK_STS(REG_0040H, 22, 1))
        {
            WR1_PROG(REG_0094H, 0x00000800U);

            HW_SCE_p_func101(0x845afecbU, 0x1e3cf8b3U, 0xa60bbf12U, 0x25eb4499U);
        }
        else
        {
            HW_SCE_p_func100(0x5543c832U, 0xaddf6c71U, 0x28946799U, 0xff20b5e1U);

            HW_SCE_p_func073_sub001(0x00140023U, 0x00280005U, 0x04040002U);

            HW_SCE_p_func073_sub003(0x00001414U, 0x00c0001dU);

            WR1_PROG(REG_0014H, 0x000000a5U);
            WAIT_STS(REG_0014H, 31, 1);
            WR1_PROG(REG_002CH, change_endian_long(0x00000002U));

            HW_SCE_p_func073_sub001(0x00140005U, 0x000f0000U, 0x0404000aU);

            WR1_PROG(REG_00B4H, 0x000f0028U);
            WR1_PROG(REG_00B8H, 0x00140005U);

            WR1_PROG(REG_00A4H, 0x04040000U);
            WR1_PROG(REG_0008H, 0x00020000U);
            WR1_PROG(REG_00A0H, 0x20010001U);
            WAIT_STS(REG_00A8H, 0, 1);
            WR1_PROG(REG_00ACH, 0x00000001U);
            WR1_PROG(REG_0040H, 0x00000d00U);

            HW_SCE_p_func073_sub001(0x00140019U, 0x00280005U, 0x04040002U);

            HW_SCE_p_func073_sub001(0x00690028U, 0x00190000U, 0x0404000aU);

            WR1_PROG(REG_0040H, 0x00210000U);

            HW_SCE_p_func073_sub001(0x00280069U, 0x00190000U, 0x0404000aU);

            WR1_PROG(REG_0040H, 0x00210000U);

            HW_SCE_p_func100(0x980a9850U, 0x1168a1b3U, 0x75c496c6U, 0x4908265bU);
            WR1_PROG(REG_0040H, 0x00400000U);
            WR1_PROG(REG_0024H, 0x00000000U);

            if (CHCK_STS(REG_0040H, 22, 1))
            {
                WR1_PROG(REG_0094H, 0x00000800U);

                HW_SCE_p_func101(0x64e43117U, 0x9024a6c6U, 0xcfeb8075U, 0x42f5f02eU);
            }
            else
            {
                WR1_PROG(REG_0094H, 0x0000b400U);
                WR1_PROG(REG_0094H, 0xfdec21a6U);

                HW_SCE_p_func101(0xcd2816fbU, 0x6aef2141U, 0xa979352bU, 0x0b3998b5U);
            }
        }
    }

    WR1_PROG(REG_0094H, 0x38008800U);
    WR1_PROG(REG_0094H, 0xfdec21a6U);
    WR1_PROG(REG_009CH, 0x00000080U);
    WR1_PROG(REG_0040H, 0x00A60000U);

    WR1_PROG(REG_0094H, 0x00007c07U);
    WR1_PROG(REG_0040H, 0x00602000U);
    WR1_PROG(REG_0024H, 0x00000000U);
}

static fsp_err_t HW_SCE_EcdsaSignatureVerificationSub (const uint32_t InData_CurveType[],
                                                     const uint32_t InData_Key[],
                                                     const uint32_t InData_MsgDgst[],
                                                     const uint32_t InData_Signature[],
                                                     const uint32_t InData_DomainParam[])
{
    if (RD1_MASK(REG_006CH, 0x00000017U) != 0)
    {
        return FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT;
    }

    WR1_PROG(REG_0070H, 0x00f10001U);
    WR1_PROG(REG_004CH, 0x00000000U);

    WR1_PROG(REG_0014H, 0x000000c7U);
    WR1_PROG(REG_009CH, 0x80010000U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, InData_CurveType[0]);
    WR1_PROG(REG_0024H, 0x00000000U);

    WR1_PROG(REG_0094H, 0x3420a800U);
    WR1_PROG(REG_0094H, 0x00000003U);
    WR1_PROG(REG_0094H, 0x2000b400U);
    WR1_PROG(REG_0094H, 0x00000002U);

    WR1_PROG(REG_00A0H, 0x20010000U);
    WR1_PROG(REG_0014H, 0x00000fc5U);
    WR1_PROG(REG_00B0H, 0x00001469U);
    WAIT_STS(REG_0014H, 31, 1);
    WR8_ADDR(REG_002CH, &InData_Signature[0]);

    WR1_PROG(REG_00B0H, 0x0000146eU);
    WAIT_STS(REG_0014H, 31, 1);
    WR8_ADDR(REG_002CH, &InData_Signature[8]);

    WR1_PROG(REG_0014H, 0x000007c5U);
    WR1_PROG(REG_00B0H, 0x00001472U);
    WAIT_STS(REG_0014H, 31, 1);
    WR8_ADDR(REG_002CH, &InData_MsgDgst[0]);

    WR1_PROG(REG_0014H, 0x00000fc5U);
    WR1_PROG(REG_00B0H, 0x0000347aU);
    WAIT_STS(REG_0014H, 31, 1);
    WR16_ADDR(REG_002CH, &InData_Key[0]);

    WR1_PROG(REG_0014H, 0x000000a7U);
    WR1_PROG(REG_009CH, 0x800100e0U);
    WAIT_STS(REG_0014H, 31, 1);
    WR1_PROG(REG_002CH, change_endian_long(0x000000f1U));
    WR1_PROG(REG_0024H, 0x00000000U);

    HW_SCE_p_func101(0xe15614a3U, 0x87c408eeU, 0x973d4a41U, 0x0f401335U);
    HW_SCE_p_func073(InData_DomainParam);

    HW_SCE_p_func100(0xa0a1055cU, 0x03f5911aU, 0x0f09da46U, 0x0e38d219U);
    WR1_PROG(REG_0040H, 0x00400000U);
    WR1_PROG(REG_0024H, 0x00000000U);

    if (CHCK_STS(REG_0040H, 22, 1))
    {
        HW_SCE_p_func102(0xe6f8c284U, 0x8537a667U, 0x3d26b23fU, 0x803a8387U);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_ERR_CRYPTO_SCE_FAIL;
    }
    else
    {
        HW_SCE_p_func102(0xf79ea955U, 0x8a062501U, 0xd2cd3129U, 0x4572974bU);
        WR1_PROG(REG_006CH, 0x00000040U);
        WAIT_STS(REG_0020H, 12, 0);

        return FSP_SUCCESS;
    }
}

/*
 * Match ecdsa_alt.c: keep field elements as big-endian bytes, then pass (uint32_t *).
 * Do not rebuild logical BE words; WR*_ADDR on LE RX plus __LIT domain params
 * expect that memory image. Cast when the pointer is 4-byte aligned to avoid a copy.
 */

int rsip_ecdsa_p256_verify_hash(
    const uint8_t hash[RSIP_ECDSA_P256_HASH_SIZE],
    const uint8_t sig[RSIP_ECDSA_P256_SIG_SIZE],
    const uint8_t pubkey[RSIP_ECDSA_P256_PUBKEY_SIZE])
{
    uint32_t curve_type[1];
    uint32_t key_w[16];
    uint32_t dig_w[8];
    uint32_t sig_w[16];
    const uint32_t *p_dig;
    const uint32_t *p_sig;
    const uint32_t *p_key;
    fsp_err_t err;

    if (hash == NULL || sig == NULL || pubkey == NULL) {
        return -1;
    }
    if (pubkey[0] != 0x04u) {
        return -1;
    }

    /* pubkey+1 is 4-byte aligned only when pubkey itself sits at 4k+3. */
    if (((uintptr_t)hash & 3u) == 0u) {
        p_dig = (const uint32_t *)(const void *)hash;
    } else {
        memcpy(dig_w, hash, 32u);
        p_dig = dig_w;
    }

    if (((uintptr_t)sig & 3u) == 0u) {
        p_sig = (const uint32_t *)(const void *)sig;
    } else {
        memcpy(sig_w, sig, 64u);
        p_sig = sig_w;
    }

    {
        const uint8_t *xy = pubkey + 1;
        if (((uintptr_t)xy & 3u) == 0u) {
            p_key = (const uint32_t *)(const void *)xy;
        } else {
            memcpy(key_w, xy, 64u);
            p_key = key_w;
        }
    }

    curve_type[0] = RSIP_CURVE_TYPE_NIST_P256;

    err = HW_SCE_EcdsaSignatureVerificationSub(
        curve_type, p_key, p_dig, p_sig, DomainParam_NIST_P256);

    return (int)err;
}

int rsip_ecdsa_p256_selftest(void)
{
    /* RFC 6979 A.2.5, message "sample". Constants only for this test. */
    static const uint8_t hash[32] = {
        0xAF,0x2B,0xDB,0xE1,0xAA,0x9B,0x6E,0xC1,0xE2,0xAD,0xE1,0xD6,0x94,0xF4,0x1F,0xC7,
        0x1A,0x83,0x1D,0x02,0x68,0xE9,0x89,0x15,0x62,0x11,0x3D,0x8A,0x62,0xAD,0xD1,0xBF
    };
    static const uint8_t pubkey[65] = {
        0x04,
        0x60,0xFE,0xD4,0xBA,0x25,0x5A,0x9D,0x31,0xC9,0x61,0xEB,0x74,0xC6,0x35,0x6D,0x68,
        0xC0,0x49,0xB8,0x92,0x3B,0x61,0xFA,0x6C,0xE6,0x69,0x62,0x2E,0x60,0xF2,0x9F,0xB6,
        0x79,0x03,0xFE,0x10,0x08,0xB8,0xBC,0x99,0xA4,0x1A,0xE9,0xE9,0x56,0x28,0xBC,0x64,
        0xF2,0xF1,0xB2,0x0C,0x2D,0x7E,0x9F,0x51,0x77,0xA3,0xC2,0x94,0xD4,0x46,0x22,0x99
    };
    static const uint8_t sig[64] = {
        0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,0x9C,0xD4,0x5E,0x81,0xD6,
        0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,0xA8,0x4E,0xAF,0x37,0x16,
        0xF7,0xCB,0x1C,0x94,0x2D,0x65,0x7C,0x41,0xD4,0x36,0xC7,0xA1,0xB6,0xE2,0x9F,0x65,
        0xF3,0xE9,0x00,0xDB,0xB9,0xAF,0xF4,0x06,0x4D,0xC4,0xAB,0x2F,0x84,0x3A,0xCD,0xA8
    };
    uint8_t bad_sig[64];
    int rc;

    rc = rsip_ecdsa_p256_verify_hash(hash, sig, pubkey);
    if (rc != 0) {
        return rc;
    }

    memcpy(bad_sig, sig, 64);
    bad_sig[63] ^= 0x01u;
    rc = rsip_ecdsa_p256_verify_hash(hash, bad_sig, pubkey);
    if (rc == 0) {
        return -100;
    }
    return 0;
}
