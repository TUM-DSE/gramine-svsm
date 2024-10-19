#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#include "ld.c"
#include "libc.c"

static int ld(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) ld_linux_x86_64_so_2;
    *out_size = ld_linux_x86_64_so_2_len;

    return 0;
}

static int libc(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) libc_so_6;
    *out_size = libc_so_6_len;

    return 0;
}

int init_libfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("lib");

    struct pseudo_node* node = pseudo_add_str(root, "ld-linux-x86-64.so.2", &ld);
    node->str.no_free = true;

    node = pseudo_add_str(root, "libc.so.6", &libc);
    node->str.no_free = true;

    return 0;
}
