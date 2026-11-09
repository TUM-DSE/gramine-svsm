/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Whether the ELF loader (execute_loadcmd in libos_rtld.c) zeroes the rest of a PT_LOAD
 * segment's last file page, the bytes from p_vaddr + p_filesz to the end of that page.
 *
 * Linux (fs/binfmt_elf.c, elf_load) and glibc's ld.so (_dl_map_segments) zero there only when
 * the segment has a bss (p_memsz > p_filesz). Otherwise the page shows the file's own bytes past
 * the segment: the next section, padding, or zeros past the end of the file. Gramine used to zero
 * the tail of every segment. For a read-only segment that costs two PalVirtualMemoryProtect calls
 * (writable, then back) and, where the page is a zero-copy alias of a runtime image, a private
 * copy of it in the monitor - per segment, per exec (UnixBench X2: execl and its ld.so have
 * three such segments each).
 *
 * So a read-only segment without a bss keeps the file's bytes, as on Linux. A writable segment
 * is zeroed as before (no PAL call: the page is already a private, writable copy), and so is a
 * read-only segment with a bss, also when the bss ends inside the last file page.
 * `libos.elf.zero_readonly_tail = true` in the manifest restores the old zeroing for read-only
 * segments too.
 *
 * Kept free of LibOS types so that a host test can include it as is.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * data_end: p_vaddr + p_filesz, mem_end: p_vaddr + p_memsz (neither page-aligned).
 * Returns true when the loader leaves [data_end, page end) as the file has it.
 */
static inline bool elf_keep_file_tail(bool writable, uint64_t data_end, uint64_t mem_end,
                                      bool zero_readonly_tail) {
    return !writable && mem_end == data_end && !zero_readonly_tail;
}
