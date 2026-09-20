/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * The spin-yield hook declared in cpu.h. Null by default, which is the bare
 * PAUSE every host but the SVSM PAL wants; see the comment there.
 */

#include <stddef.h>

#include "cpu.h"

void (*g_cpu_relax_yield)(void) = NULL;
