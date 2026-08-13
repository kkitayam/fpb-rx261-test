/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Koji KITAYAMA */

#ifndef SYSTEM_H
#define SYSTEM_H

#include <stdint.h>

void system_init(void) __attribute__((section(".text.system_init")));
void system_reset(void) __attribute__((noreturn));
void prepare_handoff(void);
void jump_to_firmware(uint32_t entry_point) __attribute__((noreturn));
void halt(void) __attribute__((noreturn));

#endif /* SYSTEM_H */
