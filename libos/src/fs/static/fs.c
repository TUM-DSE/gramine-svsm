/* Placeholder for the legacy xxd bake (tools/fn/filesystem/fs.py, BAKE=1).
 * Since the LibOS/runtime split the runtime files come from a runtime image
 * mounted by libos_fs_image.c, so this unit is intentionally empty: one
 * libsysdb.so serves every runtime. fs.py overwrites it (and the two headers
 * in libos/include/) when a runtime is still baked in the old way. */
#include "libos_fs.h"
#include "libos_fs_pseudo.h"
