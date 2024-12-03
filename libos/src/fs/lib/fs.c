#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#include "ld.c"
//#include "ld2.c"
#include "libc.c"
#include "helloworld.c"
#include "nop.c"
#include "nop_static.c"
#include "cpuid.c"
#include "cpuid_static.c"

#define __DEFINE_LIBOS_FS_PSEUDO_NODE(name, data, size) \
    static int name(struct libos_dentry* dent, char** out_data, size_t* out_size) { \
        __UNUSED(dent); \
        *out_data = (char*) data; \
        *out_size = size; \
        return 0; \
    }

#define __ADD_NODE(name, data, size) \
    node = pseudo_add_str(root, name, &data); \
    node->str.no_free = true; \
    node->perm = PSEUDO_PERM_LINK; \
    do {} while (0)

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

__DEFINE_LIBOS_FS_PSEUDO_NODE(helloworld_, helloworld, helloworld_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(nop_, nop, nop_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(nop_static_, nop_static, nop_static_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(cpuid__, cpuid_, cpuid_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(cpuid_static_, cpuid_static, cpuid_static_len)

int init_libfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("lib");

    struct pseudo_node* node = pseudo_add_str(root, "ld-linux-x86-64.so.2", &ld);
    node->str.no_free = true;

    node = pseudo_add_str(root, "libc.so.6", &libc);
    node->str.no_free = true;

    __ADD_NODE("helloworld", helloworld_, helloworld_len);
    __ADD_NODE("nop", nop_, nop_len);
    __ADD_NODE("nop_static", nop_static_, nop_static_len);
    __ADD_NODE("cpuid_", cpuid__, cpuid_len);
    __ADD_NODE("cpuid_static", cpuid_static_, cpuid_static_len);

    return 0;
}
