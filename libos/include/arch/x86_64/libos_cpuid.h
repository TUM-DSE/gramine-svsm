/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Get CPU feature flags.
 *
 * \param[out] out_cpu_flags  On success, set to CPU feature flags.
 *
 * \returns 0 on success, negative on failure.
 *
 * This function returns a new buffer with CPU feature flags, the caller is responsible to free it
 * afterwards.
 */
int libos_get_cpu_flags(char** out_cpu_flags);

/*!
 * \brief Answer a CPUID for userspace (GRAMINE_CALL_CPUID) from the LibOS's table.
 *
 * \param leaf_subleaf  The leaf in bits 0-31, the subleaf in bits 32-63.
 * \param user_regs     Where EAX, EBX, ECX and EDX go (user memory, checked).
 *
 * \returns 0 on success; -ENOSYS when `libos.cpuid_table = false`, -EFAULT for a bad buffer, or
 * the PAL's error. Nothing is written on failure.
 */
long libos_cpuid_call(unsigned long leaf_subleaf, uint32_t* user_regs);
