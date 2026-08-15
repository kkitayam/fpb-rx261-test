/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Koji KITAYAMA */

#include <stddef.h>
#include <string.h>
#include "system.h"
#include "rx261_core.h"
#include "iodefine.h"

#define HOCO_ENABLED 0u
#define HOCO_64MHZ 0u
#define HIGH_SPEED_MODE 0u
#define TRANSITION_COMPLETED 0u
#define SELECT_HOCO 1u

union OFS1 {
    unsigned long LONG;
    struct {
#ifdef __RX_LITTLE_ENDIAN__
			unsigned long VDSEL : 2;
			unsigned long LVDAS : 1;
			unsigned long FASTSTUP : 1;
			unsigned long VDSEL2 : 1;
			unsigned long  : 3;
			unsigned long HOCOEN : 1;
			unsigned long  : 3;
			unsigned long HOCOFRQ : 2;
			unsigned long  : 18;
#else
			unsigned long  : 18;
			unsigned long HOCOFRQ : 2;
			unsigned long  : 3;
			unsigned long HOCOEN : 1;
			unsigned long  : 3;
			unsigned long VDSEL2 : 1;
			unsigned long FASTSTUP : 1;
			unsigned long LVDAS : 1;
			unsigned long VDSEL : 2;
#endif
	} BIT;
};

union SCKCR {
    unsigned long LONG;
    struct {
#ifdef __RX_LITTLE_ENDIAN__
			unsigned long PCKD : 4;
			unsigned long  : 4;
			unsigned long PCKB : 4;
			unsigned long PCKA : 4;
			unsigned long  : 8;
			unsigned long ICK : 4;
			unsigned long FCK : 4;
#else
			unsigned long FCK : 4;
			unsigned long ICK : 4;
			unsigned long  : 8;
			unsigned long PCKA : 4;
			unsigned long PCKB : 4;
			unsigned long  : 4;
			unsigned long PCKD : 4;
#endif
	} BIT;
};

static const uint32_t g_ofs1 __attribute__((section(".ofs1"),used)) = 0xFFFFCEFFu; /* HOCO run at 64MHz */

static inline void rx_smovb(void *dst, const void *src, size_t len)
{
    register void *r1 __asm("r1") = dst;
    register const void *r2 __asm("r2") = src;
    register size_t r3 __asm("r3") = len;

    __asm volatile (
        "smovb"
        : "+r"(r1), "+r"(r2), "+r"(r3)
        :
        : "memory"
    );
}

void _init(void) {
    /* A dummy function for C runtime initialization */
}

void system_init(void)
{
    /* HOCO must be running at 64MHz */
    const union OFS1 ofs1 = { .LONG = OFSM.OFS1.LONG };
    if (HOCO_ENABLED != ofs1.BIT.HOCOEN || HOCO_64MHZ != ofs1.BIT.HOCOFRQ) return;

    /* Transition to high-speed mode */
    SYSTEM.PRCR.WORD = 0xA502;
    SYSTEM.OPCCR.BIT.OPCM = HIGH_SPEED_MODE;
    SYSTEM.PRCR.WORD = 0xA500;
    while (TRANSITION_COMPLETED != SYSTEM.OPCCR.BIT.OPCMTSF) ;

    FLASH.MEMWAITR.WORD = 0xAA01;  /* Enable wait cycle */

    const union SCKCR sckcr = {
        .BIT = {
            .FCK  = 0u,   /* FCK = 64/1 = 64MHz */
            .ICK  = 0u,   /* ICK = 64/1 = 64MHz */
            .PCKD = 0u,  /* PCKD = 64/1 = 64MHz */
            .PCKB = 1u,  /* PCKB = 64/2 = 32MHz */
            .PCKA = 0u,  /* PCKA = 64/1 = 64MHz */
        }
    };
    SYSTEM.PRCR.WORD       = 0xA501;
    SYSTEM.SCKCR.LONG       = sckcr.LONG;
    SYSTEM.SCKCR3.BIT.CKSEL = SELECT_HOCO;
    SYSTEM.PRCR.WORD        = 0xA500;
}

void system_reset(void)
{
RESET:
    SYSTEM.PRCR.WORD = 0xA502;
    SYSTEM.SWRR      = 0xA501;
    SYSTEM.PRCR.WORD = 0xA500;
    goto RESET;
}

void prepare_handoff(void)
{
}

void jump_to_firmware(uint32_t entry_point)
{
    typedef void (*entry_func_t)(void);
    entry_func_t entry = (entry_func_t)entry_point;
    entry();
END:
    __WAIT();
    goto END;
}

void halt(void)
{
END:
    __WAIT();
    goto END;
}

void gptw_start_freerun(void)
{
    SYSTEM.PRCR.WORD = 0xA502;
    MSTP(GPTW) = 0;
    SYSTEM.PRCR.WORD = 0xA500;
    GPTW7.GTCR.LONG = 1;
}

uint32_t gptw_get_count(void)
{
    return GPTW7.GTCNT;
}

int memcmp(const void* s1, const void* s2, size_t n)
{
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;
    for (size_t i = 0; i < n; ++i) {
        if (p1[i] != p2[i]) return (int)p1[i] - (int)p2[i];
    }
    return 0;
}

void *memmove(void *dest, const void *src, size_t n)
{
    if (dest < src) { /* forward */
        memcpy(dest, src, n);
    } else {          /* backward */
        uint8_t *d = (uint8_t *)dest + n - 1;
        const uint8_t *s = (const uint8_t *)src + n - 1;
        rx_smovb(d, s, n);
    }
    return dest;
}