/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2014 Renesas Electronics Corporation.
 * Derived from Renesas FIT r_flash_rx (Flash Type 1 / no-FCU).
 */

#ifndef FLASH_TYPE1_H
#define FLASH_TYPE1_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize flash hardware (Data Flash access enable, write enable).
// Call once from main before any write/erase.
void flash_type1_init(void);

// Write data to Code Flash or Data Flash.
// address : destination (DF 0x00100000.. or CF high addresses)
// data    : source buffer
// size    : byte count (DF: any, CF: multiple of 8)
// Returns 0 on success, negative on error.
int flash_type1_write(uintptr_t address, const void *data, size_t size);

// Erase the single block that contains address.
// DF block = 256 bytes, CF block = 2 KB.
// Returns 0 on success, negative on error.
int flash_type1_erase_sector(uintptr_t address);

#ifdef __cplusplus
}
#endif

#endif /* FLASH_TYPE1_H */
