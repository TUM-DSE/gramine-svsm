
#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#define __DEFINE_LIBOS_FS_PSEUDO_NODE(name, data, size) \
    static int name(struct libos_dentry* dent, char** out_data, size_t* out_size) { \
        __UNUSED(dent); \
        *out_data = (char*) data; \
        *out_size = size; \
        return 0; \
    }

#define __ADD_NODE(name, data) do{\
    node = pseudo_add_str(root, name, &data); \
    node->str.no_free = true; \
    node->perm = PSEUDO_PERM_LINK; \
    } while (0)

#define __ADD_DIR(name) struct pseudo_node* tmp = pseudo_add_dir(root, name); struct pseudo_node* root = tmp; (void)root;

#include "files/test__stress.h"
#include "files/test__test.h"
#include "files/test__churn.h"
#include "files/lib__libgcc_sdotsodot1.h"
#include "files/lib__libpthreaddotsodot0.h"
#include "files/lib__libmdotsodot6.h"
#include "files/lib__librtdotsodot1.h"
#include "files/lib__libcudartdotsodot12.h"
#include "files/lib__libdldotsodot2.h"
#include "files/lib__libstdcppppdotsodot6.h"
#include "files/lib__libcudadotsodot1.h"
#include "files/lib__cudotso.h"
#include "files/lib__libcdotsodot6.h"
#include "files/lib__lddashlinuxdashx86dash64dotsodot2.h"

__DEFINE_LIBOS_FS_PSEUDO_NODE(test__stress_, test__stress, test__stress_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(test__test_, test__test, test__test_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(test__churn_, test__churn, test__churn_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libgcc_sdotsodot1_, lib__libgcc_sdotsodot1, lib__libgcc_sdotsodot1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libpthreaddotsodot0_, lib__libpthreaddotsodot0, lib__libpthreaddotsodot0_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libmdotsodot6_, lib__libmdotsodot6, lib__libmdotsodot6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__librtdotsodot1_, lib__librtdotsodot1, lib__librtdotsodot1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libcudartdotsodot12_, lib__libcudartdotsodot12, lib__libcudartdotsodot12_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libdldotsodot2_, lib__libdldotsodot2, lib__libdldotsodot2_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libstdcppppdotsodot6_, lib__libstdcppppdotsodot6, lib__libstdcppppdotsodot6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libcudadotsodot1_, lib__libcudadotsodot1, lib__libcudadotsodot1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__cudotso_, lib__cudotso, lib__cudotso_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__libcdotsodot6_, lib__libcdotsodot6, lib__libcdotsodot6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(lib__lddashlinuxdashx86dash64dotsodot2_, lib__lddashlinuxdashx86dash64dotsodot2, lib__lddashlinuxdashx86dash64dotsodot2_len)

int init_static_fs_test() {
    struct pseudo_node* root = pseudo_add_root_dir("test"); (void)root;
    struct pseudo_node* node; (void)node;

    __ADD_NODE("stress", test__stress_);
    __ADD_NODE("test", test__test_);
    __ADD_NODE("churn", test__churn_);

    return 0;
}

int init_static_fs_lib() {
    struct pseudo_node* root = pseudo_add_root_dir("lib"); (void)root;
    struct pseudo_node* node; (void)node;

    __ADD_NODE("libgcc_s.so.1", lib__libgcc_sdotsodot1_);
    __ADD_NODE("libpthread.so.0", lib__libpthreaddotsodot0_);
    __ADD_NODE("libm.so.6", lib__libmdotsodot6_);
    __ADD_NODE("librt.so.1", lib__librtdotsodot1_);
    __ADD_NODE("libcudart.so.12", lib__libcudartdotsodot12_);
    __ADD_NODE("libdl.so.2", lib__libdldotsodot2_);
    __ADD_NODE("libstdc++.so.6", lib__libstdcppppdotsodot6_);
    __ADD_NODE("libcuda.so.1", lib__libcudadotsodot1_);
    __ADD_NODE("cu.so", lib__cudotso_);
    __ADD_NODE("libc.so.6", lib__libcdotsodot6_);
    __ADD_NODE("ld-linux-x86-64.so.2", lib__lddashlinuxdashx86dash64dotsodot2_);

    return 0;
}
