/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <stdint.h>
#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"

typedef void (*loader_callback)(void);

noreturn void pal_svsm_main(void) 
{

	uint64_t instance_id = 0; // Will be initialized in pal_main via _PalRandomBitsRead function
	PAL_HANDLE parent_process = NULL;
	PAL_HANDLE first_thread;
	const char** arguments;
	const char** environments;
	loader_callback callback;

	__UNUSED(first_thread);
	__UNUSED(arguments);
	__UNUSED(environments);
	__UNUSED(callback);
	//crash();
	pal_main(instance_id, parent_process, NULL, NULL, NULL, NULL);
}

/* must implement "pal_start", and call "pal_main" inside */
void pal_start(void);
void pal_start(void)
{
	pal_svsm_main();
}

