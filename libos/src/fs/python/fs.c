#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "perm.h"

#include "python3.c"

static int python(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) python3;
    *out_size = python3_len;

    return 0;
}

int init_pythonfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("python");

    struct pseudo_node* node = pseudo_add_str(root, "python3", &python);
    node->str.no_free = true;
    node->perm = PERM_r_xr_xr_x;

    return 0;
}
