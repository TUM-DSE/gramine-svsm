#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "perm.h"

#include "python.c"
#include "stdlib.c"

static int python_bin(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) python;
    *out_size = python_len;

    return 0;
}

static int stdlib(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) python311_zip;
    *out_size = python311_zip_len;

    return 0;
}

int init_pythonfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("python");

    struct pseudo_node* node = pseudo_add_str(root, "python", &python_bin);
    node->str.no_free = true;
    node->perm = PERM_r_xr_xr_x;

    node = pseudo_add_str(root, "stdlib.zip", &stdlib);
    node->str.no_free = true;

    return 0;
}
