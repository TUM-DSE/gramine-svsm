#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#include "ld.c"

#include "libc.c"
#include "libm.c"
#include "libz.c"
#include "libexpat.c"
// #include "libblas.c"
#include "libgcc_s.c"
// #include "liblapack.c"
// #include "libgfortran.c"
#include "libffi.c"
#include "libstdc++.c"
#include "libcrypt.c"
#include "libpthread.c"
#include "libdl.c"
#include "librt.c"
// #include "libutil.c"
#include "libuuid.c"
#include "libbz2.c"
#include "libgdbm.c"
#include "libgdbm_compat.c"
#include "libssl.c"
#include "libcrypto.c"
#include "liblzma.c"
#include "libsqlite3.c"


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


__DEFINE_LIBOS_FS_PSEUDO_NODE(ld, ld_linux_x86_64_so_2, ld_linux_x86_64_so_2_len)

static int libc(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    *out_data = (char*) libc_so_6;
    *out_size = libc_so_6_len;

    return 0;
}

__DEFINE_LIBOS_FS_PSEUDO_NODE(libm, libm_so_6, libm_so_6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libz, libz_so_1, libz_so_1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libexpat, libexpat_so_1, libexpat_so_1_len)
/*
__DEFINE_LIBOS_FS_PSEUDO_NODE(libblas, libblas_so_3, libblas_so_3_len)
*/
__DEFINE_LIBOS_FS_PSEUDO_NODE(libgcc_s, libgcc_s_so_1, libgcc_s_so_1_len)
/*
__DEFINE_LIBOS_FS_PSEUDO_NODE(liblapack, liblapack_so_3, liblapack_so_3_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libgfortran, libgfortran_so_5, libgfortran_so_5_len)
*/
__DEFINE_LIBOS_FS_PSEUDO_NODE(libffi, libffi_so_8, libffi_so_8_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libstdcpp, libstdc___so_6, libstdc___so_6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libcrypt, libcrypt_so_1, libcrypt_so_1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libpthread, libpthread_so_0, libpthread_so_0_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libdl, libdl_so_2, libdl_so_2_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(librt, librt_so_1, librt_so_1_len)
/*
__DEFINE_LIBOS_FS_PSEUDO_NODE(libutil, libutil_so_1, libutil_so_1_len)
*/
__DEFINE_LIBOS_FS_PSEUDO_NODE(libuuid, libuuid_so_1, libuuid_so_1_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libbz2, libbz2_so_1_0, libbz2_so_1_0_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libgdbm, libgdbm_so_6, libgdbm_so_6_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libgdbm_compat, libgdbm_compat_so_4, libgdbm_compat_so_4_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libssl, libssl_so_3, libssl_so_3_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libcrypto, libcrypto_so_3, libcrypto_so_3_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(liblzma, liblzma_so_5, liblzma_so_5_len)
__DEFINE_LIBOS_FS_PSEUDO_NODE(libsqlite3, libsqlite3_so_0, libsqlite3_so_0_len)



int init_libfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("lib");

    struct pseudo_node* node = pseudo_add_str(root, "ld-linux-x86-64.so.2", &ld);
    node->str.no_free = true;

    // libc.so.6 is the C standard library
    __ADD_NODE("libc.so.6", libc, 0);

    // libm.so.6 is needed for python
    __ADD_NODE("libm.so.6", libm, 0);

    // libz.so.1 is needed for python
    __ADD_NODE("libz.so.1", libz, 0);

    // libexpat.so.1 is needed for python
    __ADD_NODE("libexpat.so.1", libexpat, 0);

    /*
    // libblas.so.3 is needed by numpy?
    __ADD_NODE("libblas.so.3", libblas, 0);
    */

    // libgcc_s.so.1 is needed by numpy?
    __ADD_NODE("libgcc_s.so.1", libgcc_s, 0);

    /*
    // liblapack.so.3 is needed by numpy?
    __ADD_NODE("liblapack.so.3", liblapack, 0);

    // libgfortran.so.5 is needed by numpy?
    __ADD_NODE("libgfortran.so.5", libgfortran, 0);
    */

    // libffi.so.8 is needed by python
    __ADD_NODE("libffi.so.8", libffi, 0);

    // libstdc++.so.6 is needed by scipy?
    __ADD_NODE("libstdc++.so.6", libstdcpp, 0);

    // libcrypt.so.1 is needed for python?
    __ADD_NODE("libcrypt.so.1", libcrypt, 0);

    // libpthread.so.0 is needed for python?
    __ADD_NODE("libpthread.so.0", libpthread, 0);

    // libdl.so.2 is needed for python?
    __ADD_NODE("libdl.so.2", libdl, 0);

    // librt.so.1 is needed for 411
    __ADD_NODE("librt.so.1", librt, 0);

    /*
    // libutil.so.1 is needed for python?
    __ADD_NODE("libutil.so.1", libutil, 0);
    */

    // libuuid.so.1 is needed for python
    __ADD_NODE("libuuid.so.1", libuuid, 0);

    // libbz2.so.1.0 is needed for python
    __ADD_NODE("libbz2.so.1.0", libbz2, 0);

    // libgdbm.so.6 is needed for python
    __ADD_NODE("libgdbm.so.6", libgdbm, 0);

    // libgdbm_compat.so.4 is needed for python
    __ADD_NODE("libgdbm_compat.so.4", libgdbm_compat, 0);

    // libssl.so.3 is needed for python
    __ADD_NODE("libssl.so.3", libssl, 0);

    // libcrypto.so.3 is needed for python
    __ADD_NODE("libcrypto.so.3", libcrypto, 0);

    // liblzma.so.5 is needed for python
    __ADD_NODE("liblzma.so.5", liblzma, 0);

    // libsqlite3.so.0 is needed for python
    __ADD_NODE("libsqlite3.so.0", libsqlite3, 0);

    return 0;
}
